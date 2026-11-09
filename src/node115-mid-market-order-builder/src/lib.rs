//! Evidence-bounded model of the six node #115 mid-price market-order builders.

pub const TARGET_SHA256: &str = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301";
pub const RECORD_SIZE: usize = 0xe0;
const TAG_NONE: u64 = 1 << 63;
const NO_PRICE: u64 = 0x8000_0000_0000_000a;
const UNWRITTEN: u8 = 0xa5;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuilderCopy {
    pub factor_family: FactorFamily,
    pub kind: u64,
    pub source: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FactorFamily {
    Tight,
    Wide,
}

pub const COPIES: [BuilderCopy; 6] = [
    BuilderCopy {
        factor_family: FactorFamily::Tight,
        kind: 6,
        source: 1,
    },
    BuilderCopy {
        factor_family: FactorFamily::Tight,
        kind: 6,
        source: 1,
    },
    BuilderCopy {
        factor_family: FactorFamily::Wide,
        kind: 1,
        source: 4,
    },
    BuilderCopy {
        factor_family: FactorFamily::Wide,
        kind: 1,
        source: 4,
    },
    BuilderCopy {
        factor_family: FactorFamily::Tight,
        kind: 6,
        source: 1,
    },
    BuilderCopy {
        factor_family: FactorFamily::Wide,
        kind: 1,
        source: 4,
    },
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackedTime {
    pub year_ordinal: u32,
    pub seconds: u32,
    pub nanos: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Inputs {
    pub copy: usize,
    pub bid: u64,
    pub ask: u64,
    pub side: u64,
    pub size: u64,
    pub asset: u64,
    pub decimals: u8,
    pub markets: u64,
    pub market_dex: u64,
    pub assets: u64,
    pub time: PackedTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stop {
    MarketUnwrap,
    MarketMismatch,
    AssetOutOfRange,
    DecimalsOutOfRange,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Outcome {
    NoPrice {
        tag: u64,
        value: u64,
    },
    Insert {
        asset: u64,
        limit: u64,
        record: Box<[u8; RECORD_SIZE]>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BuildError {
    Stop(Stop),
    InvalidCopy,
}

/// Reconstruct one builder, including its observable record bytes and early exits.
pub fn build(input: Inputs) -> Result<Outcome, BuildError> {
    let copy = *COPIES.get(input.copy).ok_or(BuildError::InvalidCopy)?;
    let dex = input.asset / 10_000;
    let local = input.asset % 10_000;
    if dex >= input.markets {
        return Err(BuildError::Stop(Stop::MarketUnwrap));
    }
    if input.bid == 0 || input.ask == 0 {
        return Ok(Outcome::NoPrice {
            tag: TAG_NONE,
            value: NO_PRICE,
        });
    }
    if dex != input.market_dex {
        return Err(BuildError::Stop(Stop::MarketMismatch));
    }
    if local >= input.assets {
        return Err(BuildError::Stop(Stop::AssetOutOfRange));
    }
    if input.decimals >= 7 {
        return Err(BuildError::Stop(Stop::DecimalsOutOfRange));
    }

    let mid = (input.bid & input.ask).wrapping_add((input.bid ^ input.ask) >> 1);
    let selling = input.side as u8 != 0;
    let factor = match (copy.factor_family, selling) {
        (FactorFamily::Tight, false) => 1.03,
        (FactorFamily::Tight, true) => 0.97,
        (FactorFamily::Wide, false) => 1.2,
        (FactorFamily::Wide, true) => 0.8,
    };
    let scaled = (mid as f64 * factor).round();
    let price = if !scaled.is_finite() || scaled <= 0.0 {
        0
    } else if scaled >= u64::MAX as f64 {
        u64::MAX
    } else {
        scaled as u64
    }
    .max(1);
    let tick =
        tick_size(price, input.decimals).ok_or(BuildError::Stop(Stop::DecimalsOutOfRange))?;
    let quotient = price / tick;
    let units = if selling {
        quotient.saturating_add(1)
    } else {
        quotient
    };
    let limit = units.saturating_mul(tick).max(1);
    let mut record = [UNWRITTEN; RECORD_SIZE];
    put_u64(&mut record, 0x00, 1);
    put_u64(&mut record, 0x08, input.size);
    put_u64(&mut record, 0x10, 0);
    put_u64(&mut record, 0x20, 0);
    put_u64(&mut record, 0x30, 0);
    put_u64(&mut record, 0x38, 8);
    put_u64(&mut record, 0x40, 0);
    put_u64(&mut record, 0x48, copy.kind);
    put_u64(&mut record, 0x58, TAG_NONE);
    put_u64(&mut record, 0x90, limit);
    put_u64(&mut record, 0x98, time_millis(input.time));
    record[0xa0..0xa2].copy_from_slice(&1u16.to_le_bytes());
    record[0xb2] = input.side as u8;
    put_u64(&mut record, 0xb8, 0);
    for (i, byte) in (1u8..=20).enumerate() {
        record[0xc8 + i] = byte;
    }
    record[0xdc] = copy.source;
    Ok(Outcome::Insert {
        asset: input.asset,
        limit,
        record: Box::new(record),
    })
}

pub fn tick_size(price: u64, decimals: u8) -> Option<u64> {
    if decimals >= 7 {
        return None;
    }
    let digits = if price == 0 { 1 } else { price.ilog10() + 1 };
    let base = 10u64.saturating_pow(digits.saturating_sub(5));
    let cap = 10u64.pow(6 - u32::from(decimals));
    Some(base.min(cap))
}

pub fn time_millis(time: PackedTime) -> u64 {
    let word = time.year_ordinal;
    let signed = word as i32 as i64;
    let mut year = (signed >> 13) - 1;
    let mut days = 0i64;
    if year < 0 {
        let excess = ((1 - (year + 1)) / 400) + 1;
        year += excess * 400;
        days -= excess * 146_097;
    }
    let century = year / 100;
    days +=
        i64::from((word >> 4) & 0x1ff) + ((year * 1461) >> 2) - century + (century >> 2) - 719_163;
    let millis =
        (days * 86_400 + i64::from(time.seconds)) * 1000 + i64::from(time.nanos / 1_000_000);
    millis.max(0) as u64
}

fn put_u64(record: &mut [u8; RECORD_SIZE], offset: usize, value: u64) {
    record[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    const CASES: &str = include_str!("../builder_cases.tsv");

    #[test]
    fn matches_saved_builder_outcomes_and_limits() {
        let mut checked = 0;
        for line in CASES.lines().skip(1) {
            let c: Vec<_> = line.split('\t').collect();
            let n = |i: usize| {
                u64::from_str_radix(
                    c[i].trim_start_matches("0x"),
                    if c[i].starts_with("0x") { 16 } else { 10 },
                )
                .unwrap()
            };
            let date: Vec<u32> = c[11]
                .split('/')
                .map(|v| {
                    u32::from_str_radix(
                        v.trim_start_matches("0x"),
                        if v.starts_with("0x") { 16 } else { 10 },
                    )
                    .unwrap()
                })
                .collect();
            let input = Inputs {
                copy: c[0].parse().unwrap(),
                bid: n(3),
                ask: n(4),
                side: n(5),
                size: 1234,
                asset: n(6),
                decimals: n(7) as u8,
                markets: n(8),
                market_dex: n(9),
                assets: n(10),
                time: PackedTime {
                    year_ordinal: date[0],
                    seconds: date[1],
                    nanos: date[2],
                },
            };
            match (c[12], build(input)) {
                ("insert", Ok(Outcome::Insert { limit, record, .. })) => {
                    assert_eq!(limit, n(13), "limit row {checked}");
                    assert_eq!(
                        u64::from_le_bytes(record[0x90..0x98].try_into().unwrap()),
                        limit
                    );
                }
                ("no price", Ok(Outcome::NoPrice { .. })) => {}
                ("panic unwrap", Err(BuildError::Stop(Stop::MarketUnwrap))) => {}
                (
                    "panic panic",
                    Err(BuildError::Stop(Stop::MarketMismatch | Stop::AssetOutOfRange)),
                ) => {}
                ("panic index", Err(BuildError::Stop(Stop::DecimalsOutOfRange))) => {}
                (expected, actual) => panic!("row {checked}: expected {expected}, got {actual:?}"),
            }
            checked += 1;
        }
        assert_eq!(checked, 6_810);
    }

    #[test]
    fn preserves_unwritten_record_bytes_and_documented_offsets() {
        let out = build(Inputs {
            copy: 0,
            bid: 2_500_000,
            ask: 2_500_000,
            side: 0x100,
            size: 1234,
            asset: 3,
            decimals: 0,
            markets: 1,
            market_dex: 0,
            assets: 8,
            time: PackedTime {
                year_ordinal: 0xfd0640,
                seconds: 3600,
                nanos: 5_000_000,
            },
        })
        .unwrap();
        let Outcome::Insert { record, limit, .. } = out else {
            panic!("expected insert")
        };
        assert_eq!(limit, 2_575_000);
        assert_eq!(record[0xb2], 0);
        assert_eq!(record[0x48..0x50], 6u64.to_le_bytes());
        assert_eq!(record[0xdc], 1);
        assert!(record[0xa2..0xb2].iter().all(|b| *b == UNWRITTEN));
        assert_eq!(tick_size(2_500_000, 0), Some(100));
        assert_eq!(tick_size(1, 6), Some(1));
        assert_eq!(tick_size(1, 7), None);
    }
}
