//! Successful keyed mutation and exact stop-before-diagnostic boundaries in
//! 0x4483500. Names below denote raw fields, not recovered economic identities.
#![forbid(unsafe_code)]
#[allow(dead_code)]
#[path = "../node115-quantity-change/lib.rs"]
pub mod prior;

use std::{collections::BTreeMap, num::NonZeroU32};
pub type Address = [u8; 20];
const MAX_PRODUCT: u64 = (1u64 << 63) - 2;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Row {
    pub multiplier: u64,
    pub sides: [u64; 2],
    pub budgets: [u64; 2],
    pub quantity: i64,
    pub divisor: NonZeroU32,
}
impl Row {
    /// Decodes only consumed fields in a 72-byte row. Zero divisor is outside
    /// the defined arithmetic domain; returning None is local input validation.
    pub fn decode(bytes: &[u8; 72]) -> Option<(u64, Self)> {
        fn word(b: &[u8], o: usize) -> u64 {
            u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
        }
        Some((
            word(bytes, 0x40),
            Self {
                multiplier: word(bytes, 0),
                sides: [word(bytes, 8), word(bytes, 16)],
                budgets: [word(bytes, 24), word(bytes, 32)],
                quantity: word(bytes, 40) as i64,
                divisor: NonZeroU32::new(u32::from_le_bytes(bytes[48..52].try_into().unwrap()))?,
            },
        ))
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Diagnostic {
    OldSize,
    NewSize,
    AggregateOverflow,
    AggregateUnderflow,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    Noop,
    Updated { old_cost: u64, new_cost: u64 },
    StopBefore(Diagnostic),
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Group {
    pub rows: BTreeMap<u64, Row>,
    pub aggregate: u64,
}
pub type Context = BTreeMap<Address, Group>;

/// A value or the native diagnostic boundary, never an invented callback return.
fn cost(row: &Row, quantity: i64) -> Result<u64, ()> {
    let positive = usize::from(quantity > 0);
    let mut base = row.sides[1 - positive];
    let other = row.sides[positive];
    let budget = row.budgets[positive];
    let magnitude = quantity.unsigned_abs();
    let product = u128::from(magnitude) * u128::from(row.multiplier);
    if budget.wrapping_sub(1) < other && product <= u128::from(MAX_PRODUCT) {
        let quotient = other / budget;
        if magnitude == (1u64 << 63) {
            return Err(());
        }
        if let (Some(left_budget), Some(left_other)) = (
            budget.checked_sub(magnitude * 2),
            other.checked_sub((product as u64) * 2),
        ) {
            let candidate = u128::from(quotient) * u128::from(left_budget);
            if candidate <= u128::from(MAX_PRODUCT) {
                base = base.max((candidate as u64).min(left_other));
            }
        }
    }
    Ok(base / u64::from(row.divisor.get()))
}

pub fn notify(context: &mut Context, address: Address, key: u64, new: i64) -> Outcome {
    let Some(group) = context.get_mut(&address) else {
        return Outcome::Noop;
    };
    let Some(row) = group.rows.get_mut(&key) else {
        return Outcome::Noop;
    };
    if row.quantity == new {
        return Outcome::Noop;
    }
    let Ok(old_cost) = cost(row, row.quantity) else {
        return Outcome::StopBefore(Diagnostic::OldSize);
    };
    row.quantity = new; // 0x4483692 precedes new-cost calculation and aggregate checks.
    let Ok(new_cost) = cost(row, new) else {
        return Outcome::StopBefore(Diagnostic::NewSize);
    };
    let Some(added) = group.aggregate.checked_add(new_cost) else {
        return Outcome::StopBefore(Diagnostic::AggregateOverflow);
    };
    let Some(next) = added.checked_sub(old_cost) else {
        return Outcome::StopBefore(Diagnostic::AggregateUnderflow);
    };
    group.aggregate = next;
    Outcome::Updated { old_cost, new_cost }
}
/// Resume the credited caller's real Notify boundary. The caller binds its raw
/// descriptor word to this borrowed context; mismatch is a local adapter error,
/// not a native error path or arbitrary pointer dereference.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResumeError {
    NotNotification,
    WrongContext,
}
pub fn resume_notification(
    target_word: u64,
    context: &mut Context,
    key: u64,
    boundary: &prior::Boundary,
) -> Result<Outcome, ResumeError> {
    match boundary {
        prior::Boundary::Notify {
            word,
            new_bits,
            payload,
        } => {
            if *word == 0 || *word != target_word {
                return Err(ResumeError::WrongContext);
            }
            Ok(notify(context, *payload, key, *new_bits as i64))
        }
        _ => Err(ResumeError::NotNotification),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn caller_tail(
        context: Option<&mut Context>,
        address: Address,
        key: u64,
        old: i64,
        new: i64,
    ) -> Outcome {
        let word = if context.is_some() { 123 } else { 0 };
        let observation = prior::entry(
            old,
            new,
            10,
            false,
            prior::Notification {
                word,
                payload: address,
            },
        );
        match (context, &observation.next) {
            (Some(c), prior::Boundary::Notify { .. }) => {
                resume_notification(123, c, key, &observation.next).unwrap()
            }
            _ => Outcome::Noop,
        }
    }
    #[test]
    fn real_prior_prefix_and_pointer_binding() {
        let out = prior::entry(
            0,
            1,
            10,
            false,
            prior::Notification {
                word: 123,
                payload: [1; 20],
            },
        );
        assert_eq!(out.value, 11);
        let mut c = context(row(0), 100);
        assert_eq!(
            resume_notification(124, &mut c, 7, &out.next),
            Err(ResumeError::WrongContext)
        );
        assert!(matches!(
            resume_notification(123, &mut c, 7, &out.next),
            Ok(Outcome::Updated { .. })
        ));
    }
    #[test]
    fn widened_formula_oracle() {
        let mut seed = 0x12345678u64;
        for n in 0..32768 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            let r = Row {
                multiplier: seed & 31,
                sides: [(seed >> 8) & 127, (seed >> 16) & 127],
                budgets: [(seed >> 24) & 63, (seed >> 32) & 63],
                quantity: 0,
                divisor: NonZeroU32::new(1 + ((seed >> 40) & 15) as u32).unwrap(),
            };
            let q = (n % 65) as i64 - 32;
            let index = usize::from(q > 0);
            let base = i128::from(r.sides[1 - index]);
            let other = i128::from(r.sides[index]);
            let budget = i128::from(r.budgets[index]);
            let abs = i128::from(q).abs();
            let product = abs * i128::from(r.multiplier);
            let eligible = budget > 0
                && budget <= other
                && 2 * abs <= budget
                && 2 * product <= other
                && product <= i128::from(MAX_PRODUCT);
            let candidate = if eligible {
                (other / budget) * (budget - 2 * abs)
            } else {
                0
            };
            let result = if eligible && candidate <= i128::from(MAX_PRODUCT) {
                base.max(candidate.min(other - 2 * product))
            } else {
                base
            };
            assert_eq!(
                cost(&r, q),
                Ok((result / i128::from(r.divisor.get())) as u64)
            );
        }
    }
    fn row(q: i64) -> Row {
        Row {
            multiplier: 2,
            sides: [100, 80],
            budgets: [10, 8],
            quantity: q,
            divisor: NonZeroU32::new(2).unwrap(),
        }
    }
    fn context(row: Row, aggregate: u64) -> Context {
        BTreeMap::from([(
            [1; 20],
            Group {
                rows: BTreeMap::from([(7, row)]),
                aggregate,
            },
        )])
    }
    #[test]
    fn side_selection_and_clipped_candidate() {
        let r = row(0);
        assert_eq!(cost(&r, 0), Ok(50));
        assert_eq!(cost(&r, 1), Ok(50));
        assert_eq!(cost(&r, -1), Ok(40));
        let r = Row {
            sides: [1, 100],
            budgets: [1, 10],
            multiplier: 1,
            ..r
        };
        assert_eq!(cost(&r, 1), Ok(40)); // max(1,min((100/10)*8,100-2))/2
        assert_eq!(cost(&r, 6), Ok(0)); // doubled magnitude exceeds budget: fallback
    }
    #[test]
    fn exact_identity_and_unchanged_row_are_noops() {
        let mut c = context(row(0), 90);
        let original = c.clone();
        let mut other = [1; 20];
        other[19] ^= 1;
        assert_eq!(notify(&mut c, other, 7, 1), Outcome::Noop);
        assert_eq!(notify(&mut c, [1; 20], 8, 1), Outcome::Noop);
        assert_eq!(notify(&mut c, [1; 20], 7, 0), Outcome::Noop);
        assert_eq!(c, original);
    }
    #[test]
    fn aggregate_uses_stored_old_quantity_and_preserves_neighbors() {
        let mut c = context(row(-1), 90);
        c.get_mut(&[1; 20]).unwrap().rows.insert(8, row(9));
        assert_eq!(
            caller_tail(Some(&mut c), [1; 20], 7, 999, 1),
            Outcome::Updated {
                old_cost: 40,
                new_cost: 50
            }
        );
        assert_eq!(c[&[1; 20]].aggregate, 100);
        assert_eq!(c[&[1; 20]].rows[&7].quantity, 1);
        assert_eq!(c[&[1; 20]].rows[&8].quantity, 9);
        let before = c.clone();
        assert_eq!(caller_tail(Some(&mut c), [1; 20], 7, 5, 5), Outcome::Noop);
        assert_eq!(c, before);
        assert_eq!(caller_tail(None, [1; 20], 7, 0, 1), Outcome::Noop);
    }
    #[test]
    fn diagnostic_stops_preserve_native_write_order() {
        let mut c = context(row(1), u64::MAX);
        assert_eq!(
            notify(&mut c, [1; 20], 7, 0),
            Outcome::StopBefore(Diagnostic::AggregateOverflow)
        );
        assert_eq!(c[&[1; 20]].rows[&7].quantity, 0);
        assert_eq!(c[&[1; 20]].aggregate, u64::MAX);
        let mut c = context(row(1), 0);
        assert_eq!(
            notify(&mut c, [1; 20], 7, -1),
            Outcome::StopBefore(Diagnostic::AggregateUnderflow)
        );
        assert_eq!(c[&[1; 20]].rows[&7].quantity, -1);
        assert_eq!(c[&[1; 20]].aggregate, 0);
        let r = Row {
            multiplier: 0,
            sides: [u64::MAX; 2],
            budgets: [u64::MAX; 2],
            quantity: i64::MIN,
            divisor: NonZeroU32::MIN,
        };
        let mut c = context(r, 0);
        assert_eq!(
            notify(&mut c, [1; 20], 7, 0),
            Outcome::StopBefore(Diagnostic::OldSize)
        );
        assert_eq!(c[&[1; 20]].rows[&7].quantity, i64::MIN);
        let mut c = context(Row { quantity: 0, ..r }, 0);
        assert_eq!(
            notify(&mut c, [1; 20], 7, i64::MIN),
            Outcome::StopBefore(Diagnostic::NewSize)
        );
        assert_eq!(c[&[1; 20]].rows[&7].quantity, i64::MIN);
        // MIN magnitude alone doesn't diagnose when an earlier product guard fails.
        assert!(cost(&Row { multiplier: 1, ..r }, i64::MIN).is_ok());
    }
    #[test]
    fn full_width_product_and_zero_budget_fallback() {
        assert_eq!(
            cost(
                &Row {
                    multiplier: u64::MAX,
                    ..row(0)
                },
                2
            ),
            Ok(50)
        );
        assert_eq!(
            cost(
                &Row {
                    budgets: [0; 2],
                    ..row(0)
                },
                0
            ),
            Ok(40)
        );
        assert_eq!(
            cost(
                &Row {
                    budgets: [0; 2],
                    ..row(0)
                },
                1
            ),
            Ok(50)
        );
    }
    #[test]
    fn decode_offsets_and_invalid_divisor() {
        let mut b = [0; 72];
        for (o, x) in [
            (0, 2u64),
            (8, 100),
            (16, 80),
            (24, 10),
            (32, 8),
            (40, u64::MAX),
            (64, 7),
        ] {
            b[o..o + 8].copy_from_slice(&x.to_le_bytes());
        }
        b[48..52].copy_from_slice(&2u32.to_le_bytes());
        assert_eq!(Row::decode(&b), Some((7, row(-1))));
        b[48..52].fill(0);
        assert_eq!(Row::decode(&b), None);
    }
}
