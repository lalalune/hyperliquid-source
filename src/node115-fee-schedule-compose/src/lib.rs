#![no_std]
#![forbid(unsafe_code)]
//! A conditional, source-owned composition of selected node #115 fee gates.
//! This is neither the native ABI nor a ledger or fee-calculation implementation.

#[derive(Clone, Copy, Debug)]
pub struct Tier {
    /// Four binary64 fields at offsets 0, 8, 16 and 24.
    pub values: [f64; 4],
    pub cutoff: u64,
    /// The binary64 field at offset 40.
    pub tail: f64,
}
#[derive(Clone, Copy, Debug)]
pub struct Secondary {
    pub first: f64,
    pub second: f64,
}
#[derive(Clone, Copy, Debug)]
pub struct Schedule<'a> {
    pub seeds: [f64; 4],
    pub tiers: &'a [Tier],
    pub secondary: &'a [Secondary],
    pub stake_pairs: &'a [(f64, f64)],
    /// Values at record +24 in native iterator visitation order.
    pub extra_values: &'a [f64],
    /// Fields at input offsets 0x88 and 0x90.
    pub ranges: [f64; 2],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FloorSide {
    First,
    Second,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    Rejected,
    Passed,
}

/// `floor` supplies the normal-return boolean of an unimplemented dependency;
/// it is called in native order and only if its preceding gates pass.
/// Correspondence assumes valid unaliased inputs and ordinary binary64
/// round-to-nearest with masked exceptions and DAZ/FTZ disabled.
pub fn evaluate(
    s: &Schedule<'_>,
    mut floor: impl FnMut(FloorSide, &Schedule<'_>, f64) -> bool,
) -> Outcome {
    if s.seeds
        .iter()
        .chain(s.ranges.iter())
        .chain(s.extra_values.iter())
        .any(|x| !x.is_finite())
        || s.tiers
            .iter()
            .any(|t| t.values.iter().any(|x| !x.is_finite()) || !t.tail.is_finite())
        || s.secondary
            .iter()
            .any(|t| !t.first.is_finite() || !t.second.is_finite())
    {
        return Outcome::Rejected;
    }
    let mut previous = s.seeds;
    let mut cutoff = 0_u64;
    let mut tail = 1.0_f64;
    for t in s.tiers {
        if (0..4).any(|i| t.values[i] > previous[i]) || t.cutoff <= cutoff || t.tail > tail {
            return Outcome::Rejected;
        }
        previous = t.values;
        cutoff = t.cutoff;
        tail = t.tail;
    }
    let mut p5 = s.seeds[1];
    let mut p6 = s.seeds[3];
    let mut p8 = 0.0;
    for r in s.secondary {
        if r.second > p5 || r.second > p6 || r.first <= p8 {
            return Outcome::Rejected;
        }
        p5 = r.second;
        p6 = r.second;
        p8 = r.first;
    }
    let mut p = (0.0, 0.0);
    for &(a, b) in s.stake_pairs {
        if !(a > p.0 && b > p.1) {
            return Outcome::Rejected;
        }
        p = (a, b);
    }
    if p.0 > 5.0 || p.1 > 0.5 || s.ranges.iter().any(|x| *x < 0.0 || *x > 1.0) {
        return Outcome::Rejected;
    }
    let mut sum = -0.0_f64;
    for &x in s.extra_values {
        sum += x;
    }
    if sum > 1.0 {
        return Outcome::Rejected;
    }
    if !floor(FloorSide::First, s, p.1) || !floor(FloorSide::Second, s, p.1) {
        return Outcome::Rejected;
    }
    fn cross(x: f64) -> bool {
        (0.0..=0.001).contains(&x) && (x <= 0.0 || x >= 0.0001)
    }
    fn add(x: f64) -> bool {
        x.abs() <= 0.001 && (x <= 0.0 || x >= 0.0001)
    }
    if !cross(s.seeds[0])
        || !cross(s.seeds[2])
        || !add(s.seeds[1])
        || !add(s.seeds[3])
        || s.tiers.iter().any(|t| {
            !cross(t.values[0]) || !cross(t.values[2]) || !add(t.values[1]) || !add(t.values[3])
        })
        || s.secondary.iter().any(|r| !add(r.second))
    {
        return Outcome::Rejected;
    }
    Outcome::Passed
}
