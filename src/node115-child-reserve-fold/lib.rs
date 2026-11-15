//! Selected reserve-word fold at node #115 call-result continuation.
//! This is not the whole frame finalizer. Offsets retain their raw names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameWords {
    pub word_190: u64,
    pub word_198: i64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CallResultWords {
    pub word_58: u64,
    pub word_60: i64,
    pub raw_status_70: u8,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpecialStatus54;
/// Project the two stores on the selected normal continuation after the
/// surrounding result dispatch, buffer handling and cleanup have returned.
/// Status 54 branches away earlier; its behavior is intentionally not modeled.
/// Other raw bytes are not asserted to be admitted native result variants.
/// SSTORE provenance, gas+188, refund+1a0 and the other finalizer arm are open.
pub fn fold(frame: &mut FrameWords, result: CallResultWords) -> Result<(), SpecialStatus54> {
    if result.raw_status_70 == 54 {
        return Err(SpecialStatus54);
    }
    if (1..=4).contains(&result.raw_status_70) {
        frame.word_190 = result.word_58;
        frame.word_198 = frame.word_198.saturating_add(result.word_60);
    } else {
        frame.word_190 = result.word_58.saturating_add_signed(result.word_60);
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn selected_statuses_and_special_branch() {
        let mut frame = FrameWords {
            word_190: 777,
            word_198: 12,
        };
        fold(
            &mut frame,
            CallResultWords {
                word_58: 8,
                word_60: -10,
                raw_status_70: 1,
            },
        )
        .unwrap();
        assert_eq!(
            frame,
            FrameWords {
                word_190: 8,
                word_198: 2
            }
        );
        fold(
            &mut frame,
            CallResultWords {
                word_58: 8,
                word_60: -10,
                raw_status_70: 16,
            },
        )
        .unwrap();
        assert_eq!(
            frame,
            FrameWords {
                word_190: 0,
                word_198: 2
            }
        );
        let saved = frame;
        assert_eq!(
            fold(
                &mut frame,
                CallResultWords {
                    word_58: 1,
                    word_60: 1,
                    raw_status_70: 54
                }
            ),
            Err(SpecialStatus54)
        );
        assert_eq!(frame, saved);
    }
    #[test]
    fn wide_integer_oracle_for_all_raw_bytes_and_extreme_words() {
        let unsigned = [
            0,
            1,
            7,
            i64::MAX as u64,
            1 << 63,
            (1 << 63) + 1,
            u64::MAX - 1,
            u64::MAX,
        ];
        let signed = [
            i64::MIN,
            i64::MIN + 1,
            -11,
            -1,
            0,
            1,
            11,
            i64::MAX - 1,
            i64::MAX,
        ];
        for raw_status_70 in 0..=255 {
            if raw_status_70 == 54 {
                continue;
            }
            for word_58 in unsigned {
                for word_60 in signed {
                    for initial_signed in signed {
                        let mut frame = FrameWords {
                            word_190: 123,
                            word_198: initial_signed,
                        };
                        fold(
                            &mut frame,
                            CallResultWords {
                                word_58,
                                word_60,
                                raw_status_70,
                            },
                        )
                        .unwrap();
                        let special = [1, 2, 3, 4].contains(&raw_status_70);
                        let expected_unsigned = if special {
                            word_58
                        } else {
                            (i128::from(word_58) + i128::from(word_60))
                                .clamp(0, i128::from(u64::MAX)) as u64
                        };
                        let expected_signed = if special {
                            (i128::from(initial_signed) + i128::from(word_60))
                                .clamp(i128::from(i64::MIN), i128::from(i64::MAX))
                                as i64
                        } else {
                            initial_signed
                        };
                        assert_eq!(
                            frame,
                            FrameWords {
                                word_190: expected_unsigned,
                                word_198: expected_signed
                            }
                        );
                    }
                }
            }
        }
    }
}
