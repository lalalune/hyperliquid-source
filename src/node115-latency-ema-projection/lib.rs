//! Node #115 latency-EMA row projection.
//!
//! Independently authored logical model of the normal-return behaviour of the
//! row closure `0x5a327a0..0x5a329d8` and its collector `0x5b80ea0..0x5b810ce`
//! in Linux x86-64 node #115, SHA-256
//! `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
//! Evidence: `research/work-items/RE-008-node115-latency-ema-projection`.
//!
//! The model owns no native layout. Container search, allocation, the later
//! ordering step and the consumer of the built collection are outside it.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;

/// The closure compares and copies exactly 20 key bytes.
pub const KEY_LEN: usize = 20;

/// Opaque 20-byte row key.
pub type Key = [u8; KEY_LEN];

/// The two `f64` lanes the closure reads from a found record: the numerator at
/// record `+0x10` and the denominator at record `+0x18`. Other record bytes are
/// not read on this path.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Record {
    pub num: f64,
    pub denom: f64,
}

/// The native path calls the panic entry with
/// `assertion failed: self.denom > 0.` and `base/src/ema_tracker.rs:58:13`.
/// The model reports that boundary as a value and does not model unwinding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DenominatorNotPositive;

/// One collected row: the caller's key bytes and the sanitised quotient.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Row {
    pub key: Key,
    pub value: f64,
}

/// Quotient step.
///
/// A denominator that compares ordered-equal to zero (either sign) yields
/// positive zero without reading the numerator. A denominator that is then not
/// ordered-greater than zero (negative or NaN) reaches the assertion. Otherwise
/// the result is the IEEE-754 double quotient.
pub fn quotient(record: Record) -> Result<f64, DenominatorNotPositive> {
    if record.denom == 0.0 {
        return Ok(0.0);
    }
    if record.denom > 0.0 {
        Ok(record.num / record.denom)
    } else {
        Err(DenominatorNotPositive)
    }
}

/// Raw-bit sanitisation applied to the quotient.
///
/// Zero of either sign and positive finite values (subnormal or normal) pass
/// unchanged. Positive infinity, every NaN and every negative non-zero value
/// become positive zero.
pub fn sanitize(value: f64) -> f64 {
    const SIGN: u64 = 1 << 63;
    const INFINITY: u64 = 0x7ff0_0000_0000_0000;
    let bits = value.to_bits();
    let magnitude = bits & !SIGN;
    if magnitude == 0 || (bits & SIGN == 0 && magnitude < INFINITY) {
        value
    } else {
        0.0
    }
}

/// One closure call: an absent record yields no row; a found record yields the
/// caller's key with its sanitised quotient.
pub fn project_row(
    key: &Key,
    record: Option<Record>,
) -> Result<Option<Row>, DenominatorNotPositive> {
    match record {
        None => Ok(None),
        Some(record) => Ok(Some(Row {
            key: *key,
            value: sanitize(quotient(record)?),
        })),
    }
}

/// The collector: keys are taken in iterator order, each key is looked up once,
/// absent keys are skipped and found rows are appended in that same order.
/// Nothing here orders or deduplicates rows. The assertion boundary ends the
/// collection without a row vector.
pub fn collect<'a, I, F>(keys: I, mut lookup: F) -> Result<Vec<Row>, DenominatorNotPositive>
where
    I: IntoIterator<Item = &'a Key>,
    F: FnMut(&Key) -> Option<Record>,
{
    let mut rows = Vec::new();
    for key in keys {
        if let Some(row) = project_row(key, lookup(key))? {
            rows.push(row);
        }
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    const NEG_ZERO: u64 = 1 << 63;
    const INF: u64 = 0x7ff0_0000_0000_0000;

    fn key(last: u8) -> Key {
        let mut key = [0x11; KEY_LEN];
        key[KEY_LEN - 1] = last;
        key
    }

    fn bits(value: f64) -> u64 {
        value.to_bits()
    }

    // 0x5a328d8..0x5a328de: ordered-equal zero takes the +0.0 lane and skips the
    // numerator load at 0x5a328ea.
    #[test]
    fn zero_denominator_gives_positive_zero_without_the_numerator() {
        for num in [f64::NAN, f64::INFINITY, -5.0, 7.0] {
            assert_eq!(bits(quotient(Record { num, denom: 0.0 }).unwrap()), 0);
            assert_eq!(bits(quotient(Record { num, denom: -0.0 }).unwrap()), 0);
        }
    }

    // 0x5a328e4 jbe: below, equal or unordered reaches the assertion.
    #[test]
    fn negative_and_nan_denominators_reach_the_assertion() {
        for denom in [
            -1.0,
            f64::NEG_INFINITY,
            -f64::MIN_POSITIVE,
            f64::NAN,
            -f64::NAN,
        ] {
            assert_eq!(
                quotient(Record { num: 1.0, denom }),
                Err(DenominatorNotPositive)
            );
        }
        assert_eq!(
            quotient(Record {
                num: 1.0,
                denom: f64::from_bits(NEG_ZERO | 1)
            }),
            Err(DenominatorNotPositive)
        );
    }

    // 0x5a328ef divsd.
    #[test]
    fn positive_denominator_divides() {
        assert_eq!(
            bits(
                quotient(Record {
                    num: 3.0,
                    denom: 4.0
                })
                .unwrap()
            ),
            0x3fe8_0000_0000_0000
        );
        assert_eq!(
            bits(
                quotient(Record {
                    num: 1.0,
                    denom: f64::from_bits(1)
                })
                .unwrap()
            ),
            INF
        );
        assert_eq!(
            bits(
                quotient(Record {
                    num: -1.0,
                    denom: f64::INFINITY
                })
                .unwrap()
            ),
            NEG_ZERO
        );
        assert!(quotient(Record {
            num: f64::NAN,
            denom: 2.0
        })
        .unwrap()
        .is_nan());
    }

    // Hand-derived from the branch network at 0x5a328f3..0x5a32981.
    #[test]
    fn sanitisation_matches_each_native_class() {
        let unchanged = [
            0u64,                  // +0: magnitude zero keeps xmm0
            NEG_ZERO,              // -0: magnitude zero keeps xmm0, sign included
            1,                     // smallest positive subnormal: bits-1 < 0xfffffffffffff
            0x000f_ffff_ffff_ffff, // largest positive subnormal
            0x0010_0000_0000_0000, // smallest positive normal: exponent bucket < 0x3ff
            0x3fe8_0000_0000_0000, // 0.75
            0x7fef_ffff_ffff_ffff, // largest finite
        ];
        for value in unchanged {
            assert_eq!(
                bits(sanitize(f64::from_bits(value))),
                value,
                "{value:#018x}"
            );
        }
        let cleared = [
            INF,                   // +infinity: bucket 0x3ff
            INF | 1,               // signalling NaN payload
            0x7ff8_0000_0000_0000, // quiet NaN
            0x7fff_ffff_ffff_ffff,
            NEG_ZERO | 1, // negative subnormal
            NEG_ZERO | 0x0010_0000_0000_0000,
            0xbfe8_0000_0000_0000, // -0.75
            NEG_ZERO | INF,        // -infinity
            0xfff8_0000_0000_0000, // negative NaN
        ];
        for value in cleared {
            assert_eq!(bits(sanitize(f64::from_bits(value))), 0, "{value:#018x}");
        }
    }

    // 0x5a329a7: absent record stores tag 0 and writes no key or value.
    #[test]
    fn absent_record_yields_no_row() {
        assert_eq!(project_row(&key(1), None), Ok(None));
    }

    // 0x5a32981..0x5a329a0: all 20 key bytes are copied from the caller's key.
    #[test]
    fn found_record_copies_every_key_byte() {
        for index in 0..KEY_LEN {
            let mut wanted = [0u8; KEY_LEN];
            wanted[index] = 0xa5;
            let row = project_row(
                &wanted,
                Some(Record {
                    num: 1.0,
                    denom: 2.0,
                }),
            )
            .unwrap()
            .unwrap();
            assert_eq!(row.key, wanted);
            assert_eq!(bits(row.value), 0x3fe0_0000_0000_0000);
        }
    }

    #[test]
    fn found_record_with_unusable_quotient_is_still_a_row() {
        let negative = project_row(
            &key(2),
            Some(Record {
                num: -3.0,
                denom: 4.0,
            }),
        )
        .unwrap()
        .unwrap();
        assert_eq!(bits(negative.value), 0);
        let overflow = project_row(
            &key(3),
            Some(Record {
                num: f64::MAX,
                denom: f64::MIN_POSITIVE,
            }),
        )
        .unwrap()
        .unwrap();
        assert_eq!(bits(overflow.value), 0);
        let empty = project_row(
            &key(4),
            Some(Record {
                num: 9.0,
                denom: 0.0,
            }),
        )
        .unwrap()
        .unwrap();
        assert_eq!(bits(empty.value), 0);
        let negative_zero = project_row(
            &key(5),
            Some(Record {
                num: -0.0,
                denom: 4.0,
            }),
        )
        .unwrap()
        .unwrap();
        assert_eq!(bits(negative_zero.value), NEG_ZERO);
    }

    // 0x5b80ef5..0x5b80f00 and 0x5b80fd0..0x5b80ff7: absent keys are skipped,
    // found rows keep iterator order, and the same key may be looked up again.
    #[test]
    fn collection_keeps_iterator_order_and_skips_absent_keys() {
        let keys = [key(9), key(1), key(7), key(1), key(3)];
        let rows = collect(keys.iter(), |wanted| match wanted[KEY_LEN - 1] {
            9 => Some(Record {
                num: 1.0,
                denom: 2.0,
            }),
            1 => Some(Record {
                num: 3.0,
                denom: 4.0,
            }),
            3 => Some(Record {
                num: -1.0,
                denom: 1.0,
            }),
            _ => None,
        })
        .unwrap();
        assert_eq!(
            rows,
            vec![
                Row {
                    key: key(9),
                    value: 0.5
                },
                Row {
                    key: key(1),
                    value: 0.75
                },
                Row {
                    key: key(1),
                    value: 0.75
                },
                Row {
                    key: key(3),
                    value: 0.0
                },
            ]
        );
    }

    // 0x5b80f02..0x5b80f11: no found row leaves the empty vector shape.
    #[test]
    fn collection_of_absent_keys_is_empty() {
        let keys = [key(1), key(2)];
        assert_eq!(collect(keys.iter(), |_| None), Ok(vec![]));
        assert_eq!(
            collect([].iter(), |_| Some(Record {
                num: 1.0,
                denom: 1.0
            })),
            Ok(vec![])
        );
    }

    // More than the first four-row allocation and across the growth call.
    #[test]
    fn collection_grows_past_the_first_allocation() {
        let keys: Vec<Key> = (0..70).map(key).collect();
        let rows = collect(keys.iter(), |wanted| {
            Some(Record {
                num: f64::from(wanted[KEY_LEN - 1]),
                denom: 2.0,
            })
        })
        .unwrap();
        assert_eq!(rows.len(), 70);
        for (index, row) in rows.iter().enumerate() {
            assert_eq!(row.key, keys[index]);
            assert_eq!(row.value, index as f64 / 2.0);
        }
    }

    #[test]
    fn assertion_boundary_ends_the_collection() {
        let keys = [key(1), key(2), key(3)];
        let mut lookups = 0;
        let result = collect(keys.iter(), |wanted| {
            lookups += 1;
            Some(Record {
                num: 1.0,
                denom: if wanted[KEY_LEN - 1] == 2 { -1.0 } else { 1.0 },
            })
        });
        assert_eq!(result, Err(DenominatorNotPositive));
        assert_eq!(lookups, 2);
    }
}
