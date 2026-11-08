#![no_std]

//! Safe logical projection of the node #115 outcome account routine at
//! `0x38da9e0`. This is not its native ABI or a map/parallel-collection layer.

/// The coarse weight established by the preceding settlement conversion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoarseWeight(u16);

impl CoarseWeight {
    /// Creates a weight in the native projection's reachable 0..=1000 domain.
    pub const fn new(value: u64) -> Option<Self> {
        if value <= 1_000 {
            Some(Self(value as u16))
        } else {
            None
        }
    }

    pub const fn value(self) -> u16 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TokenBalance {
    pub total: u64,
    pub held: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProjectionInput {
    pub account_address: [u8; 20],
    /// First token, second token, and the destination identifier.
    pub token_ids: [u64; 3],
    /// Explicit results from the two ordered balance-map lookups. `None` means
    /// the native map lookup was absent and therefore supplies zero balance.
    pub balances: [Option<TokenBalance>; 2],
    pub coarse_weight: CoarseWeight,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Diagnostics {
    pub first_subtraction_underflow: bool,
    pub second_subtraction_underflow: bool,
    pub payout_sum_overflow: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PayoutRow {
    pub token_id: u64,
    pub amount: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Projection {
    Skip {
        lookup_count: u8,
        lookups: [u64; 2],
        diagnostics: Diagnostics,
    },
    Error {
        code: u8,
        lookup_count: u8,
        lookups: [u64; 2],
        diagnostics: Diagnostics,
    },
    Success {
        balances: [u64; 2],
        rows: [PayoutRow; 3],
        row_count: u8,
        lookup_count: u8,
        lookups: [u64; 2],
        diagnostics: Diagnostics,
    },
}

/// Constructs the exact 20-byte token address excluded by the native routine:
/// prefix `0x32`, eleven zero bytes, then the big-endian token identifier.
pub fn reserved_token_address(token_id: u64) -> [u8; 20] {
    let mut address = [0; 20];
    address[0] = 0x32;
    address[12..20].copy_from_slice(&token_id.to_be_bytes());
    address
}

/// Applies the ordered balance gates, checked products, payout saturation,
/// and row ordering recovered for the selected account projection.
///
/// The input balance values stand for map results; the function records which
/// lookup would be reached before a return. Diagnostic flags describe only
/// paths whose callback returns. No native allocation or error niche is modeled.
pub fn project(input: ProjectionInput) -> Projection {
    if input.account_address == reserved_token_address(input.token_ids[0])
        || input.account_address == reserved_token_address(input.token_ids[1])
    {
        return Projection::Skip {
            lookup_count: 0,
            lookups: [0; 2],
            diagnostics: Diagnostics::default(),
        };
    }

    let mut lookups = [0; 2];
    lookups[0] = input.token_ids[0];
    let mut lookup_count = 1;
    let first = input.balances[0].unwrap_or_default();
    let mut diagnostics = Diagnostics::default();
    let first_available = available(first, &mut diagnostics.first_subtraction_underflow);
    if first_available != first.total {
        return Projection::Error {
            code: 19,
            lookup_count,
            lookups,
            diagnostics,
        };
    }

    let first_product = match first.total.checked_mul(u64::from(input.coarse_weight.0)) {
        Some(value) => value,
        None => {
            return Projection::Error {
                code: 14,
                lookup_count,
                lookups,
                diagnostics,
            };
        }
    };

    lookups[1] = input.token_ids[1];
    lookup_count = 2;
    let second = input.balances[1].unwrap_or_default();
    let second_available = available(second, &mut diagnostics.second_subtraction_underflow);
    if second_available != second.total {
        return Projection::Error {
            code: 19,
            lookup_count,
            lookups,
            diagnostics,
        };
    }

    let second_weight = 1_000 - u64::from(input.coarse_weight.0);
    let second_product = match second.total.checked_mul(second_weight) {
        Some(value) => value,
        None => {
            return Projection::Error {
                code: 14,
                lookup_count,
                lookups,
                diagnostics,
            };
        }
    };

    let payout = match first_product.checked_add(second_product) {
        Some(value) => value,
        None => {
            diagnostics.payout_sum_overflow = true;
            u64::MAX
        }
    };

    let mut rows = [PayoutRow::default(); 3];
    let mut row_count = 0;
    append_positive(&mut rows, &mut row_count, input.token_ids[0], first.total);
    append_positive(&mut rows, &mut row_count, input.token_ids[1], second.total);
    append_positive(&mut rows, &mut row_count, input.token_ids[2], payout);

    if row_count == 0 {
        Projection::Skip {
            lookup_count,
            lookups,
            diagnostics,
        }
    } else {
        Projection::Success {
            balances: [first.total, second.total],
            rows,
            row_count,
            lookup_count,
            lookups,
            diagnostics,
        }
    }
}

fn available(balance: TokenBalance, underflow_diagnostic: &mut bool) -> u64 {
    match balance.total.checked_sub(balance.held) {
        Some(value) => value,
        None => {
            *underflow_diagnostic = true;
            0
        }
    }
}

fn append_positive(rows: &mut [PayoutRow; 3], row_count: &mut u8, token_id: u64, amount: u64) {
    if amount != 0 {
        rows[usize::from(*row_count)] = PayoutRow { token_id, amount };
        *row_count += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CoarseWeight, Diagnostics, PayoutRow, Projection, ProjectionInput, TokenBalance, project,
        reserved_token_address,
    };

    const IDS: [u64; 3] = [11, 22, 33];
    const ADDRESS: [u8; 20] = [0x42; 20];

    fn input(
        address: [u8; 20],
        balances: [Option<TokenBalance>; 2],
        weight: u64,
        token_ids: [u64; 3],
    ) -> ProjectionInput {
        ProjectionInput {
            account_address: address,
            token_ids,
            balances,
            coarse_weight: CoarseWeight::new(weight).unwrap(),
        }
    }

    fn balance(total: u64, held: u64) -> Option<TokenBalance> {
        Some(TokenBalance { total, held })
    }

    fn reference(input: ProjectionInput) -> Projection {
        let ids = input.token_ids;
        if input.account_address == reserved_token_address(ids[0])
            || input.account_address == reserved_token_address(ids[1])
        {
            return Projection::Skip {
                lookup_count: 0,
                lookups: [0; 2],
                diagnostics: Diagnostics::default(),
            };
        }

        let first = input.balances[0].unwrap_or_default();
        let second = input.balances[1].unwrap_or_default();
        let weight = u128::from(input.coarse_weight.value());
        let mut diagnostics = Diagnostics::default();
        if first.held > first.total {
            diagnostics.first_subtraction_underflow = true;
        }
        let first_available = first.total.saturating_sub(first.held);
        if first_available != first.total {
            return Projection::Error {
                code: 19,
                lookup_count: 1,
                lookups: [ids[0], 0],
                diagnostics,
            };
        }

        let first_product = u128::from(first.total) * weight;
        if first_product > u128::from(u64::MAX) {
            return Projection::Error {
                code: 14,
                lookup_count: 1,
                lookups: [ids[0], 0],
                diagnostics,
            };
        }

        if second.held > second.total {
            diagnostics.second_subtraction_underflow = true;
        }
        let second_available = second.total.saturating_sub(second.held);
        if second_available != second.total {
            return Projection::Error {
                code: 19,
                lookup_count: 2,
                lookups: [ids[0], ids[1]],
                diagnostics,
            };
        }

        let second_product =
            u128::from(second.total) * u128::from(1_000 - input.coarse_weight.value());
        if second_product > u128::from(u64::MAX) {
            return Projection::Error {
                code: 14,
                lookup_count: 2,
                lookups: [ids[0], ids[1]],
                diagnostics,
            };
        }

        let sum = first_product + second_product;
        if sum > u128::from(u64::MAX) {
            diagnostics.payout_sum_overflow = true;
        }
        let payout = sum.min(u128::from(u64::MAX)) as u64;
        let mut rows = [PayoutRow::default(); 3];
        let mut row_count = 0;
        for (token_id, amount) in [
            (ids[0], first.total),
            (ids[1], second.total),
            (ids[2], payout),
        ] {
            if amount != 0 {
                rows[usize::from(row_count)] = PayoutRow { token_id, amount };
                row_count += 1;
            }
        }
        if row_count == 0 {
            Projection::Skip {
                lookup_count: 2,
                lookups: [ids[0], ids[1]],
                diagnostics,
            }
        } else {
            Projection::Success {
                balances: [first.total, second.total],
                rows,
                row_count,
                lookup_count: 2,
                lookups: [ids[0], ids[1]],
                diagnostics,
            }
        }
    }

    #[test]
    fn projects_the_coarse_weight_into_ordered_rows() {
        assert_eq!(
            project(input(ADDRESS, [balance(1, 0), balance(1, 0)], 500, IDS)),
            Projection::Success {
                balances: [1, 1],
                rows: [
                    PayoutRow {
                        token_id: 11,
                        amount: 1,
                    },
                    PayoutRow {
                        token_id: 22,
                        amount: 1,
                    },
                    PayoutRow {
                        token_id: 33,
                        amount: 1_000,
                    },
                ],
                row_count: 3,
                lookup_count: 2,
                lookups: [11, 22],
                diagnostics: Diagnostics::default(),
            }
        );
    }

    #[test]
    fn reserved_addresses_skip_before_balance_lookups() {
        for address in [reserved_token_address(11), reserved_token_address(22)] {
            assert_eq!(
                project(input(
                    address,
                    [balance(u64::MAX, 1), balance(1, 1)],
                    500,
                    IDS
                )),
                Projection::Skip {
                    lookup_count: 0,
                    lookups: [0; 2],
                    diagnostics: Diagnostics::default(),
                }
            );
        }
    }

    #[test]
    fn held_balance_error_precedes_second_lookup() {
        assert_eq!(
            project(input(ADDRESS, [balance(1, 1), balance(1, 0)], 500, IDS)),
            Projection::Error {
                code: 19,
                lookup_count: 1,
                lookups: [11, 0],
                diagnostics: Diagnostics::default(),
            }
        );
    }

    #[test]
    fn first_product_overflow_precedes_second_balance_error() {
        assert_eq!(
            project(input(
                ADDRESS,
                [balance(u64::MAX, 0), balance(1, 1)],
                2,
                IDS
            )),
            Projection::Error {
                code: 14,
                lookup_count: 1,
                lookups: [11, 0],
                diagnostics: Diagnostics::default(),
            }
        );
    }

    #[test]
    fn nonfatal_subtraction_underflow_is_recorded_and_zero_balance_can_skip() {
        assert_eq!(
            project(input(ADDRESS, [balance(0, 1), None], 500, IDS)),
            Projection::Skip {
                lookup_count: 2,
                lookups: [11, 22],
                diagnostics: Diagnostics {
                    first_subtraction_underflow: true,
                    second_subtraction_underflow: false,
                    payout_sum_overflow: false,
                },
            }
        );
    }

    #[test]
    fn second_product_overflow_is_reported_after_both_lookups() {
        assert_eq!(
            project(input(ADDRESS, [None, balance(u64::MAX, 0)], 0, IDS)),
            Projection::Error {
                code: 14,
                lookup_count: 2,
                lookups: [11, 22],
                diagnostics: Diagnostics::default(),
            }
        );
    }

    #[test]
    fn payout_sum_overflow_diagnoses_and_saturates() {
        let total = 36_893_488_147_419_103;
        assert_eq!(
            project(input(
                ADDRESS,
                [balance(total, 0), balance(total, 0)],
                500,
                IDS
            )),
            Projection::Success {
                balances: [total, total],
                rows: [
                    PayoutRow {
                        token_id: 11,
                        amount: total,
                    },
                    PayoutRow {
                        token_id: 22,
                        amount: total,
                    },
                    PayoutRow {
                        token_id: 33,
                        amount: u64::MAX,
                    },
                ],
                row_count: 3,
                lookup_count: 2,
                lookups: [11, 22],
                diagnostics: Diagnostics {
                    first_subtraction_underflow: false,
                    second_subtraction_underflow: false,
                    payout_sum_overflow: true,
                },
            }
        );
    }

    #[test]
    fn equal_identifiers_remain_separate_rows_and_zero_weight_keeps_balance_row() {
        assert_eq!(
            project(input(
                ADDRESS,
                [balance(2, 0), balance(2, 0)],
                500,
                [11, 11, 11]
            )),
            Projection::Success {
                balances: [2, 2],
                rows: [
                    PayoutRow {
                        token_id: 11,
                        amount: 2,
                    },
                    PayoutRow {
                        token_id: 11,
                        amount: 2,
                    },
                    PayoutRow {
                        token_id: 11,
                        amount: 2_000,
                    },
                ],
                row_count: 3,
                lookup_count: 2,
                lookups: [11, 11],
                diagnostics: Diagnostics::default(),
            }
        );
        assert_eq!(
            project(input(ADDRESS, [balance(5, 0), None], 0, IDS)),
            Projection::Success {
                balances: [5, 0],
                rows: [
                    PayoutRow {
                        token_id: 11,
                        amount: 5,
                    },
                    PayoutRow::default(),
                    PayoutRow::default(),
                ],
                row_count: 1,
                lookup_count: 2,
                lookups: [11, 22],
                diagnostics: Diagnostics::default(),
            }
        );
    }

    #[test]
    fn matches_an_independent_u128_oracle_on_boundary_and_generated_inputs() {
        let balances = [
            None,
            balance(0, 0),
            balance(0, 1),
            balance(1, 0),
            balance(1, 1),
            balance(1, 2),
            balance(100, 0),
            balance(100, 1),
            balance(u64::MAX / 1_000, 0),
            balance(u64::MAX / 500, 0),
            balance(u64::MAX, 0),
            balance(u64::MAX, u64::MAX),
        ];
        for weight in [0, 1, 2, 499, 500, 501, 999, 1_000] {
            for first in balances {
                for second in balances {
                    let input = input(ADDRESS, [first, second], weight, IDS);
                    assert_eq!(project(input), reference(input));
                }
            }
        }

        let mut state = 85u64;
        for _ in 0..4_096 {
            let weight = next(&mut state) % 1_001;
            let first_weight = weight.max(1);
            let second_weight = (1_000 - weight).max(1);
            let first = boundary_balance(&mut state, first_weight);
            let second = boundary_balance(&mut state, second_weight);
            let input = input(ADDRESS, [Some(first), Some(second)], weight, IDS);
            assert_eq!(project(input), reference(input));
        }
    }

    #[test]
    fn changing_any_reserved_address_byte_removes_that_exclusion() {
        for address in [reserved_token_address(11), reserved_token_address(22)] {
            for index in 0..20 {
                let mut changed = address;
                changed[index] ^= 1;
                let result = project(input(changed, [balance(1, 0), balance(1, 0)], 500, IDS));
                assert!(matches!(result, Projection::Success { .. }));
            }
        }
    }

    #[test]
    fn coarse_weight_constructor_rejects_unreachable_values() {
        assert!(CoarseWeight::new(1_000).is_some());
        assert!(CoarseWeight::new(1_001).is_none());
    }

    fn next(state: &mut u64) -> u64 {
        *state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        *state
    }

    fn boundary_balance(state: &mut u64, weight: u64) -> TokenBalance {
        let limit = u64::MAX / weight;
        let offset = (next(state) % 7) as i8 - 3;
        let total = if offset < 0 {
            limit.saturating_sub(u64::from(offset.unsigned_abs()))
        } else {
            limit.saturating_add(offset as u64)
        };
        let held = match next(state) % 5 {
            0..=2 => 0,
            3 => 1,
            _ => total,
        };
        TokenBalance { total, held }
    }
}
