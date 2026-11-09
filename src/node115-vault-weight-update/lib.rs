//! Selected normal snapshot and writeback continuation of node #115 0x44ad9e0.
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq)]
pub struct Value {
    pub ratio: f64,
    /// Remaining bytes of the native 48-byte value.
    pub tail: [u8; 40],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stop {
    BeforeSignedOverflow,
}

/// Assumes valid logical map/iterator and normal allocator and entry returns.
/// Inputs and map reflect a normally completed prior prepass.
pub fn continuation_after_normal_prepass(
    map: &mut BTreeMap<[u8; 20], Value>,
    target: [u8; 20],
    initial: i64,
    delta: i64,
    seed: [u8; 12],
) -> Result<(), Stop> {
    let sum = initial
        .checked_add(delta)
        .ok_or(Stop::BeforeSignedOverflow)?;
    let denom = (sum.max(0) as f64) / 1_000_000.0;
    let old = (initial as f64) / 1_000_000.0;
    let increment = (delta as f64) / 1_000_000.0;
    let mut snapshot: BTreeMap<[u8; 20], f64> = map
        .iter()
        .map(|(key, value)| (*key, value.ratio * old))
        .collect();
    *snapshot.entry(target).or_insert(0.0) += increment;
    for (key, numerator) in snapshot {
        let ratio = if denom == 0.0 || !numerator.is_finite() || numerator < 1e-7 {
            0.0
        } else {
            let value = numerator / denom;
            if value == f64::INFINITY {
                0.0
            } else {
                value
            }
        };
        let value = map.entry(key).or_insert_with(|| {
            let mut tail = [0; 40];
            tail[16..28].copy_from_slice(&seed);
            tail[28..40].copy_from_slice(&seed);
            Value { ratio: 0.0, tail }
        });
        value.ratio = ratio;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn v(ratio: f64, marker: u8) -> Value {
        Value {
            ratio,
            tail: [marker; 40],
        }
    }
    #[test]
    fn snapshot_seed_and_writeback_preserve_old_metadata() {
        let mut m = BTreeMap::from([([1; 20], v(0.25, 9)), ([2; 20], v(0.75, 8))]);
        continuation_after_normal_prepass(&mut m, [1; 20], 4_000_000, 2_000_000, [3; 12]).unwrap();
        assert_eq!(m[&[1; 20]].ratio, 0.5);
        assert_eq!(m[&[2; 20]].ratio, 0.5);
        assert_eq!(m[&[1; 20]].tail, [9; 40]);
        assert_eq!(m[&[2; 20]].tail, [8; 40]);
    }
    #[test]
    fn vacancy_has_repeated_seed_and_snapshot_uses_prior_values() {
        let mut m = BTreeMap::from([([1; 20], v(1.0, 7))]);
        continuation_after_normal_prepass(&mut m, [2; 20], 1_000_000, 1_000_000, [4; 12]).unwrap();
        assert_eq!(m[&[1; 20]].ratio, 0.5);
        assert_eq!(m[&[2; 20]].ratio, 0.5);
        assert_eq!(&m[&[2; 20]].tail[..16], &[0; 16]);
        assert_eq!(&m[&[2; 20]].tail[16..], &[4; 24]);
    }
    #[test]
    fn exceptional_numerators_and_zero_denominator_become_positive_zero() {
        let mut m = BTreeMap::from([
            ([1; 20], v(f64::NAN, 1)),
            ([2; 20], v(-1.0, 2)),
            ([3; 20], v(f64::INFINITY, 3)),
        ]);
        continuation_after_normal_prepass(&mut m, [4; 20], 1_000_000, 0, [0; 12]).unwrap();
        for item in m.values() {
            assert_eq!(item.ratio.to_bits(), 0);
        }
        continuation_after_normal_prepass(&mut m, [4; 20], 0, 0, [0; 12]).unwrap();
        for item in m.values() {
            assert_eq!(item.ratio.to_bits(), 0);
        }
    }
    #[test]
    fn stop_paths_do_not_mutate() {
        let mut m = BTreeMap::from([([1; 20], v(0.5, 1))]);
        let before = m.clone();
        assert_eq!(
            continuation_after_normal_prepass(&mut m, [2; 20], i64::MAX, 1, [0; 12]),
            Err(Stop::BeforeSignedOverflow)
        );
        assert_eq!(m, before);
    }
    #[test]
    fn minimum_numerator_is_inclusive_and_infinite_quotient_is_zeroed() {
        let boundary = 1e-7_f64;
        let below = f64::from_bits(boundary.to_bits() - 1);
        let above = f64::from_bits(boundary.to_bits() + 1);
        let mut m = BTreeMap::from([
            ([1; 20], v(below, 1)),
            ([2; 20], v(boundary, 2)),
            ([3; 20], v(above, 3)),
            ([4; 20], v(f64::MAX, 4)),
        ]);
        // initial/1e6 = 1; positive total is 1e-6, making MAX / denom overflow.
        continuation_after_normal_prepass(&mut m, [5; 20], 1_000_000, -999_999, [0; 12]).unwrap();
        assert_eq!(m[&[1; 20]].ratio, 0.0);
        assert_eq!(m[&[2; 20]].ratio, boundary / 1e-6);
        assert_eq!(m[&[3; 20]].ratio, above / 1e-6);
        assert_eq!(m[&[4; 20]].ratio, 0.0);
    }
}
