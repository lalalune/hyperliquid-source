#![no_std]
//! Value projection of two node115 interior arithmetic spans; no native ABI.

/// Observations at the two explicit instruction frontiers, not native errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Observation {
    Word(u64),
    DiagnosticBoundary,
}

/// Six raw fields of the synthetic immutable row; names imply no economic unit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Row {
    pub multiplier: u64,
    pub a: u64,
    pub b: u64,
    pub c: u64,
    pub d: u64,
    pub signed: i64,
}

/// Observe RBX before 0x4483b14, or arrival before 0x4483b65.
/// Other incoming registers, flags, whole-function helpers and ABI are excluded.
pub fn observe(row: Row) -> Observation {
    const LIMIT: u128 = (1u128 << 63) - 2;
    let (base, opposite, denominator) = if row.signed > 0 {
        (row.a, row.b, row.d)
    } else {
        (row.b, row.a, row.c)
    };
    let retain = Observation::Word(base);
    let magnitude = row.signed.unsigned_abs();
    let product = u128::from(magnitude) * u128::from(row.multiplier);
    if denominator.wrapping_sub(1) >= opposite {
        return retain;
    }
    // The previous guard establishes a nonzero divisor. The original performs
    // this division before the product guard, using a 32-bit fast path if fit.
    let quotient = opposite / denominator;
    if product > LIMIT {
        return retain;
    }
    if magnitude == 1u64 << 63 {
        return Observation::DiagnosticBoundary;
    }
    let Some(remaining_denominator) = denominator.checked_sub(magnitude * 2) else {
        return retain;
    };
    let Some(remaining_opposite) = opposite.checked_sub((product as u64) * 2) else {
        return retain;
    };
    let candidate = u128::from(quotient) * u128::from(remaining_denominator);
    if candidate > LIMIT {
        return retain;
    }
    Observation::Word(base.max(remaining_opposite.min(candidate as u64)))
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::{observe, Observation, Row};
    #[test]
    fn frozen_original_frontiers() {
        let cases = include_str!(
            "../../research/work-items/RE-004-signed-bound-kernel-115/target-smoke.tsv"
        );
        for line in cases.lines() {
            let fields: std::vec::Vec<_> = line.split('\t').collect();
            assert_eq!(fields.len(), 7);
            let values: std::vec::Vec<u64> =
                fields[..6].iter().map(|s| s.parse().unwrap()).collect();
            let row = Row {
                multiplier: values[0],
                a: values[1],
                b: values[2],
                c: values[3],
                d: values[4],
                signed: values[5] as i64,
            };
            let actual = match observe(row) {
                Observation::Word(v) => std::format!("C:{v}"),
                Observation::DiagnosticBoundary => std::string::String::from("N"),
            };
            assert_eq!(actual, fields[6], "input {:?}", values);
        }
    }
}
