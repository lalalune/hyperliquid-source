//! Selected valid logical state path through 0x446bdd0 and 0x3beb980.
//! Prior #4170 supplies mode-4 dispatch/magnitude/division; #4403 supplies the
//! credited special-address dependency. Diagnostic, unwind and storage lifetime
//! are explicit boundaries, not arbitrary callback returns.
#[allow(unused_attributes)] // Unchanged prior module carries a crate-root no_std attribute.
#[path = "../node115-margin-range/position-modes/src/lib.rs"]
pub mod position_modes;
use std::collections::BTreeMap;
pub const SPECIAL: [[u8; 20]; 8] = [
    [
        1, 4, 97, 193, 78, 20, 106, 195, 95, 228, 34, 113, 189, 193, 19, 78, 227, 28, 112, 58,
    ],
    [
        49, 202, 131, 149, 207, 131, 125, 224, 139, 36, 218, 63, 102, 14, 119, 118, 29, 251, 151,
        75,
    ],
    [
        118, 132, 132, 247, 226, 235, 182, 117, 197, 120, 56, 54, 108, 2, 174, 153, 186, 42, 155, 8,
    ],
    [
        198, 76, 192, 11, 70, 16, 27, 212, 10, 161, 195, 18, 17, 149, 232, 92, 11, 9, 24, 216,
    ],
    [
        7, 190, 213, 192, 131, 6, 224, 38, 121, 126, 94, 169, 60, 41, 58, 188, 86, 115, 194, 173,
    ],
    [
        147, 226, 85, 29, 130, 29, 218, 16, 128, 163, 114, 240, 176, 75, 134, 70, 131, 32, 51, 61,
    ],
    [
        161, 80, 153, 163, 11, 191, 46, 104, 148, 45, 111, 76, 67, 215, 13, 4, 250, 234, 176, 160,
    ],
    [
        223, 194, 75, 7, 123, 193, 66, 90, 209, 222, 167, 91, 203, 111, 129, 88, 225, 13, 243, 3,
    ],
];
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Position {
    pub key: u64,
    pub tag: u32,
    pub divisor: u32,
    pub size: i64,
}
impl Position {
    pub fn decode(row: &[u8; 72]) -> Self {
        Self {
            key: u64::from_le_bytes(row[..8].try_into().unwrap()),
            tag: u32::from_le_bytes(row[8..12].try_into().unwrap()),
            divisor: u32::from_le_bytes(row[12..16].try_into().unwrap()),
            size: i64::from_le_bytes(row[24..32].try_into().unwrap()),
        }
    }
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Account {
    pub base: i64,
    pub positions: Vec<Position>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Context {
    pub accounts: BTreeMap<[u8; 20], Account>,
    pub reserves: BTreeMap<[u8; 20], u64>,
    pub oracles: Vec<i64>,
    pub cap: u8,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    OracleIndex,
    NegativeOracle,
    ProductOverflow,
    ZeroDivisor,
    NetOverflow,
    RequirementOverflow,
    MagnitudeOverflow,
    RequirementSignedRange,
    DifferenceOverflow,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stop {
    pub row: Option<usize>,
    pub stage: Stage,
}
/// Input positions are in native visitation order and address maps have exact
/// twenty-byte keys. Native indexing/hash/storage validity are premises.
pub fn quantity(context: &Context, address: [u8; 20]) -> Result<u64, Stop> {
    let empty = Account::default();
    let account = context.accounts.get(&address).unwrap_or(&empty);
    let mut net = account.base;
    let mut requirement = 0u64;
    let mut magnitude_sum = 0u64;
    for (index, row) in account.positions.iter().enumerate() {
        if row.tag != 0 {
            continue;
        }
        let stop = |stage| Stop {
            row: Some(index),
            stage,
        };
        let oracle_index = (row.key % 10_000) as usize;
        let oracle = *context
            .oracles
            .get(oracle_index)
            .ok_or(stop(Stage::OracleIndex))?;
        if oracle < 0 {
            return Err(stop(Stage::NegativeOracle));
        }
        let product = oracle
            .checked_mul(row.size)
            .ok_or(stop(Stage::ProductOverflow))?;
        let magnitude = position_modes::magnitude(product);
        let plan = position_modes::dispatch(4, row.divisor, context.cap)
            .map_err(|_| stop(Stage::ZeroDivisor))?;
        let position_modes::ModePlan::Divide(divisor) = plan else {
            unreachable!("mode 4 yields division");
        };
        let cost =
            position_modes::quotient(magnitude, divisor).map_err(|_| stop(Stage::ZeroDivisor))?;
        net = net.checked_add(product).ok_or(stop(Stage::NetOverflow))?;
        requirement = requirement
            .checked_add(cost)
            .ok_or(stop(Stage::RequirementOverflow))?;
        magnitude_sum = magnitude_sum
            .checked_add(magnitude)
            .ok_or(stop(Stage::MagnitudeOverflow))?;
    }
    let fail = |stage| Stop { row: None, stage };
    let cost = i64::try_from(requirement).map_err(|_| fail(Stage::RequirementSignedRange))?;
    let difference = net
        .checked_sub(cost)
        .ok_or(fail(Stage::DifferenceOverflow))?;
    let reserve = if SPECIAL.contains(&address) {
        0
    } else {
        context.reserves.get(&address).copied().unwrap_or(0)
    };
    Ok((difference.max(0) as u64).saturating_sub(reserve))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn ctx(base: i64, size: i64) -> Context {
        Context {
            accounts: BTreeMap::from([(
                [0; 20],
                Account {
                    base,
                    positions: vec![Position {
                        key: 10_000,
                        tag: 0,
                        divisor: 10,
                        size,
                    }],
                },
            )]),
            reserves: BTreeMap::new(),
            oracles: vec![5],
            cap: 4,
        }
    }
    #[test]
    fn actual_rows_to_difference_and_reserve() {
        let mut c = ctx(100, 6);
        c.reserves.insert([0; 20], 9);
        assert_eq!(quantity(&c, [0; 20]), Ok(114)); // 100+30-floor(30/4)-9
        assert_eq!(quantity(&c, [1; 20]), Ok(0));
        c.accounts.get_mut(&[0; 20]).unwrap().positions[0].size = -6;
        assert_eq!(quantity(&c, [0; 20]), Ok(54));
    }
    #[test]
    fn exact_address_and_special_dependency() {
        let mut c = ctx(100, 0);
        let a = c.accounts[&[0; 20]].clone();
        for key in SPECIAL {
            c.accounts.insert(key, a.clone());
            c.reserves.insert(key, u64::MAX);
            assert_eq!(quantity(&c, key), Ok(100));
        }
        c.reserves.insert([0; 20], 101);
        assert_eq!(quantity(&c, [0; 20]), Ok(0));
        for index in 0..20 {
            let mut key = [0; 20];
            key[index] = 1;
            assert_eq!(quantity(&c, key), Ok(0));
        }
    }
    #[test]
    fn skip_precedes_lookup_and_divisor() {
        let mut c = ctx(100, 99);
        let p = &mut c.accounts.get_mut(&[0; 20]).unwrap().positions[0];
        p.tag = 1;
        p.key = u64::MAX;
        p.divisor = 0;
        c.cap = 0;
        c.oracles.clear();
        assert_eq!(quantity(&c, [0; 20]), Ok(100));
        c.accounts.get_mut(&[0; 20]).unwrap().positions[0].tag = 0;
        assert_eq!(quantity(&c, [0; 20]).unwrap_err().stage, Stage::OracleIndex);
    }
    #[test]
    fn signed_min_and_failure_order() {
        let mut c = ctx(0, i64::MIN);
        c.oracles[0] = 1;
        c.cap = 1;
        assert_eq!(
            quantity(&c, [0; 20]).unwrap_err().stage,
            Stage::RequirementSignedRange
        );
        c.cap = 2;
        assert_eq!(
            quantity(&c, [0; 20]).unwrap_err().stage,
            Stage::DifferenceOverflow
        );
        c.oracles[0] = -1;
        assert_eq!(
            quantity(&c, [0; 20]).unwrap_err().stage,
            Stage::NegativeOracle
        );
        c.oracles[0] = 2;
        c.cap = 0;
        assert_eq!(
            quantity(&c, [0; 20]).unwrap_err().stage,
            Stage::ProductOverflow
        );
        c.accounts.get_mut(&[0; 20]).unwrap().positions[0].size = 1;
        assert_eq!(quantity(&c, [0; 20]).unwrap_err().stage, Stage::ZeroDivisor);
    }
    #[test]
    fn unused_magnitude_fold_still_stops() {
        let mut c = ctx(0, i64::MAX);
        c.oracles[0] = 1;
        c.cap = 10;
        let a = c.accounts.get_mut(&[0; 20]).unwrap();
        a.positions.push(Position {
            key: 0,
            tag: 0,
            divisor: 10,
            size: -i64::MAX,
        });
        a.positions.push(Position {
            key: 0,
            tag: 0,
            divisor: 10,
            size: 2,
        });
        assert_eq!(
            quantity(&c, [0; 20]),
            Err(Stop {
                row: Some(2),
                stage: Stage::MagnitudeOverflow
            })
        );
    }
    #[test]
    fn row_decode_and_independent_widened_oracle() {
        let mut raw = [0xa5; 72];
        raw[..8].copy_from_slice(&10_000u64.to_le_bytes());
        raw[8..12].copy_from_slice(&0u32.to_le_bytes());
        raw[12..16].copy_from_slice(&10u32.to_le_bytes());
        raw[24..32].copy_from_slice(&6i64.to_le_bytes());
        assert_eq!(
            Position::decode(&raw),
            ctx(100, 6).accounts[&[0; 20]].positions[0]
        );
        let mut count = 0;
        for base in [-100, 0, 100, 1000] {
            for size in -20i64..=20 {
                for cap in 1..=16u8 {
                    for reserve in [0, 1, 100, 1000] {
                        let mut c = ctx(base, size);
                        c.cap = cap;
                        c.reserves.insert([0; 20], reserve);
                        let product = i128::from(size) * 5;
                        let cost = product.abs() / i128::from(cap.min(10));
                        let expected =
                            (i128::from(base) + product - cost).max(0) - i128::from(reserve);
                        assert_eq!(quantity(&c, [0; 20]), Ok(expected.max(0) as u64));
                        count += 1;
                    }
                }
            }
        }
        assert_eq!(count, 10496);
    }
}
