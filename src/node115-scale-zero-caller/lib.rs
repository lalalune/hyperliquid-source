//! Two actual key lookups and the selected scaler-to-result/float handoff.
//! Logical valid-map model. Native tree/ring allocation and the positive suffix
//! after the floating helper boundary are not implemented.
use std::collections::BTreeMap;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Value {
    pub tag: u32,
    pub saved_word: u64,
    pub scale_operand: u64,
}
impl Value {
    pub fn decode(bytes: &[u8; 176]) -> Self {
        Self {
            tag: u32::from_le_bytes(bytes[..4].try_into().unwrap()),
            saved_word: u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
            scale_operand: u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Metadata {
    pub byte48: u8,
    pub byte49: u8,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScaleBoundary {
    MetadataIndex,
    NegativeExponent,
    PowerOverflow,
    ZeroDenominator,
}
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Outcome {
    /// Native output word 3 and byte +8 = 9. No scaler invocation.
    MissingKey,
    /// Native output word 2. It retains no reason distinguishing wrong first
    /// tag, genuine zero, or overflow-to-zero.
    Word2,
    StopBeforeScaleFailure(ScaleBoundary),
    /// Original program is about to call slot 0x64e1890 at 0x3693e59.
    BeforeFloatHelper {
        scaled: u64,
        saved_word: u64,
        input: f64,
    },
}
/// Prior #5071's scale contract, expressed with widened owned arithmetic for
/// this caller integration. This is credited dependency behavior, not a new
/// discovery of the scale leaf. The original division helper is not executed.
fn scale(numerator: u64, denominator: u64, metadata: Metadata) -> Result<u64, ScaleBoundary> {
    let exponent = metadata
        .byte49
        .checked_sub(metadata.byte48)
        .ok_or(ScaleBoundary::NegativeExponent)?;
    let power = 10u64
        .checked_pow(u32::from(exponent))
        .ok_or(ScaleBoundary::PowerOverflow)?;
    if denominator == 0 {
        return Err(ScaleBoundary::ZeroDenominator);
    }
    let n = u128::from(numerator) * u128::from(power);
    let d = u128::from(denominator);
    let rounded = n.div_ceil(d);
    Ok(u64::try_from(rounded).unwrap_or(0))
}
pub fn prefix(
    map: &BTreeMap<u64, Value>,
    first: u64,
    second: u64,
    metadata: &[Metadata],
) -> Outcome {
    let Some(a) = map.get(&first) else {
        return Outcome::MissingKey;
    };
    let Some(b) = map.get(&second) else {
        return Outcome::MissingKey;
    };
    if a.tag != 1 {
        return Outcome::Word2;
    }
    let Ok(index) = usize::try_from(second) else {
        return Outcome::StopBeforeScaleFailure(ScaleBoundary::MetadataIndex);
    };
    let Some(m) = metadata.get(index) else {
        return Outcome::StopBeforeScaleFailure(ScaleBoundary::MetadataIndex);
    };
    let value = match scale(a.scale_operand, b.scale_operand, *m) {
        Ok(v) => v,
        Err(e) => return Outcome::StopBeforeScaleFailure(e),
    };
    if value == 0 {
        return Outcome::Word2;
    }
    Outcome::BeforeFloatHelper {
        scaled: value,
        saved_word: a.saved_word,
        input: (value as f64) * 0.98,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn m(n: u64, d: u64) -> BTreeMap<u64, Value> {
        BTreeMap::from([
            (
                0,
                Value {
                    tag: 1,
                    saved_word: 77,
                    scale_operand: n,
                },
            ),
            (
                1,
                Value {
                    tag: 99,
                    saved_word: 88,
                    scale_operand: d,
                },
            ),
        ])
    }
    fn meta(e: u8) -> [Metadata; 2] {
        [
            Metadata {
                byte48: 0,
                byte49: 0,
            },
            Metadata {
                byte48: 0,
                byte49: e,
            },
        ]
    }
    #[test]
    fn genuine_and_overflow_zero_have_identical_native_result() {
        assert_eq!(prefix(&m(0, 1), 0, 1, &meta(1)), Outcome::Word2);
        assert_eq!(prefix(&m(u64::MAX, 1), 0, 1, &meta(1)), Outcome::Word2);
        assert_eq!(
            prefix(&m(u64::MAX, 1), 0, 1, &meta(0)),
            Outcome::BeforeFloatHelper {
                scaled: u64::MAX,
                saved_word: 77,
                input: 18446744073709551616.0 * 0.98
            }
        );
    }
    #[test]
    fn both_lookups_precede_tag_gate_and_scale() {
        let mut map = m(3, 2);
        map.get_mut(&0).unwrap().tag = 0;
        assert_eq!(prefix(&map, 0, 1, &[]), Outcome::Word2);
        map.remove(&1);
        assert_eq!(prefix(&map, 0, 1, &[]), Outcome::MissingKey);
        assert_eq!(prefix(&map, 99, 1, &[]), Outcome::MissingKey);
    }
    #[test]
    fn second_tag_is_not_checked_and_second_key_selects_metadata() {
        let map = m(3, 2);
        assert_eq!(
            prefix(&map, 0, 1, &meta(1)),
            Outcome::BeforeFloatHelper {
                scaled: 15,
                saved_word: 77,
                input: 14.7
            }
        );
        assert_eq!(
            prefix(&map, 0, 0, &meta(1)),
            Outcome::BeforeFloatHelper {
                scaled: 1,
                saved_word: 77,
                input: 0.98
            }
        );
        assert_eq!(
            prefix(&map, 0, 1, &[]),
            Outcome::StopBeforeScaleFailure(ScaleBoundary::MetadataIndex)
        );
    }
    #[test]
    fn scaler_stops_precede_zero_result() {
        assert_eq!(
            prefix(&m(0, 0), 0, 1, &meta(0)),
            Outcome::StopBeforeScaleFailure(ScaleBoundary::ZeroDenominator)
        );
        assert_eq!(
            prefix(&m(0, 0), 0, 1, &meta(20)),
            Outcome::StopBeforeScaleFailure(ScaleBoundary::PowerOverflow)
        );
        let mut md = meta(0);
        md[1] = Metadata {
            byte48: 1,
            byte49: 0,
        };
        assert_eq!(
            prefix(&m(0, 1), 0, 1, &md),
            Outcome::StopBeforeScaleFailure(ScaleBoundary::NegativeExponent)
        );
    }
    #[test]
    fn exact_value_offsets_and_unsigned_keys() {
        let mut bytes = [0xa5; 176];
        bytes[..4].copy_from_slice(&1u32.to_le_bytes());
        bytes[8..16].copy_from_slice(&77u64.to_le_bytes());
        bytes[16..24].copy_from_slice(&3u64.to_le_bytes());
        assert_eq!(Value::decode(&bytes), m(3, 2)[&0]);
        let mut map = m(3, 2);
        map.insert(u64::MAX, Value::decode(&bytes));
        assert_eq!(
            prefix(&map, u64::MAX, 1, &meta(0)),
            Outcome::BeforeFloatHelper {
                scaled: 2,
                saved_word: 77,
                input: 1.96
            }
        );
    }
    #[test]
    fn independent_ceiling_inequalities() {
        let mut cases = 0;
        for n in [0, 1, 2, 3, 19, 100, u32::MAX as u64, u64::MAX] {
            for d in [1, 2, 3, 7, 10, 97, u64::MAX] {
                for e in 0..=19 {
                    let got = scale(n, d, meta(e)[1]).unwrap();
                    let product = u128::from(n) * 10u128.pow(u32::from(e));
                    if product > u128::from(d) * u128::from(u64::MAX) || product == 0 {
                        assert_eq!(got, 0);
                    } else {
                        assert!(u128::from(got) * u128::from(d) >= product);
                        assert!(u128::from(got - 1) * u128::from(d) < product);
                    }
                    cases += 1;
                }
            }
        }
        assert_eq!(cases, 1120);
    }
}
