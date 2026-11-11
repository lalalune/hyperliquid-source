//! Bounded arithmetic plan from the selected node115 midpoint builders.
//!
//! Supplied best-pair/metadata/time are logical inputs; no live book reader,
//! native allocation, insert call, or unspecified record bytes are modeled.
#![no_std]
#![forbid(unsafe_code)]

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Family {
    Narrow,
    Wide,
}

/// Logical Gregorian time; accepted range is an owned wrapper precondition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Time {
    pub year: i32,
    pub ordinal: u16,
    pub seconds: u32,
    pub nanos: u32,
}

/// Selected market row after caller-controlled lookup.
#[derive(Clone, Copy, Debug)]
pub struct Market<'a> {
    pub count: u64,
    pub selected_dex: u64,
    pub decimals: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    MarketIndex,
    TickMarket,
    Decimals,
    InvalidTime,
}

/// Only fields with selected evidence are exposed; native padding/ownership omitted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Plan {
    pub asset: u64,
    pub size: u64,
    pub side: u8,
    pub user: [u8; 20],
    pub limit: u64,
    pub timestamp_ms: u64,
    pub kind: u64,
    pub source: u8,
}

fn leap(y: i64) -> bool {
    y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)
}
fn millis(t: Time) -> Option<u64> {
    let year = i64::from(t.year);
    if !(-262143..=262142).contains(&t.year)
        || t.ordinal == 0
        || u32::from(t.ordinal) > if leap(year) { 366 } else { 365 }
        || t.seconds >= 86400
        || t.nanos >= 2_000_000_000
        || (t.nanos >= 1_000_000_000 && t.seconds % 60 != 59)
    {
        return None;
    }
    let prior = year - 1;
    let days = prior * 365 + prior.div_euclid(4) - prior.div_euclid(100)
        + prior.div_euclid(400)
        + i64::from(t.ordinal)
        - 719_163;
    let value = (days * 86400 + i64::from(t.seconds)) * 1000 + i64::from(t.nanos / 1_000_000);
    Some(value.max(0) as u64)
}

// Round nonnegative finite binary64 to integer, ties away; >= 2^52 is integral.
fn round_positive(x: f64) -> f64 {
    if x >= 4_503_599_627_370_496.0 {
        return x;
    }
    let whole = x as u64;
    if x - whole as f64 >= 0.5 {
        (whole + 1) as f64
    } else {
        whole as f64
    }
}

/// Builds the observed plan or the first mapped guard outcome. `Ok(None)` is
/// the no-price result. Errors are owned categories, not native panic objects.
#[allow(clippy::too_many_arguments)]
pub fn plan(
    asset: u64,
    market: Market<'_>,
    pair: (u64, u64),
    side: u8,
    size: u64,
    user: [u8; 20],
    family: Family,
    time: Time,
) -> Result<Option<Plan>, Error> {
    let dex = asset / 10_000;
    if dex >= market.count {
        return Err(Error::MarketIndex);
    }
    if pair.0 == 0 || pair.1 == 0 {
        return Ok(None);
    }
    let mid = (pair.0 & pair.1) + ((pair.0 ^ pair.1) >> 1);
    let factor = match (family, side == 0) {
        (Family::Narrow, true) => 1.03,
        (Family::Narrow, false) => 0.97,
        (Family::Wide, true) => 1.2,
        (Family::Wide, false) => 0.8,
    };
    let price = (round_positive((mid as f64) * factor) as u64).max(1);
    let local = (asset % 10_000) as usize;
    if dex != market.selected_dex || local >= market.decimals.len() {
        return Err(Error::TickMarket);
    }
    let decimals = market.decimals[local];
    if decimals >= 7 {
        return Err(Error::Decimals);
    }
    let mut digits = 1u32;
    let mut rest = price;
    while rest >= 10 {
        rest /= 10;
        digits += 1;
    }
    let exponent = digits.saturating_sub(5);
    let tick = 10u64.pow(exponent).min(10u64.pow(6 - u32::from(decimals)));
    let mut q = price / tick;
    if side != 0 {
        q = q.saturating_add(1);
    }
    let limit = q.saturating_mul(tick).max(1);
    let timestamp_ms = millis(time).ok_or(Error::InvalidTime)?;
    let (kind, source) = match family {
        Family::Narrow => (6, 1),
        Family::Wide => (1, 4),
    };
    Ok(Some(Plan {
        asset,
        size,
        side,
        user,
        limit,
        timestamp_ms,
        kind,
        source,
    }))
}
