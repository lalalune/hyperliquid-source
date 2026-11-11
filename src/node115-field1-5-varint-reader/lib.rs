#![no_std]
//! Logical projection of the #115 scalar reader family with error field1 = 5.
//! This is not the original ABI, enum naming, or a complete codec.

/// Raw normal-return outcomes observed for this reader family.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadOutcome {
    /// Rawtag 0x12; a decoded u64 is stored at result +0x8.
    Value(u64),
    /// Rawtag 0x00; `additional` is stored at result +0x8.
    NeedMore { additional: u64 },
    /// Rawtag 0x02; mode-1 byte-count overflow or limit refusal.
    ChargeRejected,
    /// Rawtag 0x03; raw constructor fields, not inferred enum names.
    Invalid { field1: u8, field2: u8 },
}

impl ReadOutcome {
    pub const fn raw_tag(self) -> u8 {
        match self {
            Self::Value(_) => 0x12,
            Self::NeedMore { .. } => 0x00,
            Self::ChargeRejected => 0x02,
            Self::Invalid { .. } => 0x03,
        }
    }
}

/// Safe reader state for the observed cursor, limit and charge fields.
pub struct Reader<'a> {
    remaining: &'a [u8],
    mode: u32,
    limit: u64,
    charged: u64,
}

impl<'a> Reader<'a> {
    pub const fn new(input: &'a [u8], mode: u32, limit: u64, charged: u64) -> Self {
        Self {
            remaining: input,
            mode,
            limit,
            charged,
        }
    }

    pub const fn remaining(&self) -> &'a [u8] {
        self.remaining
    }

    pub const fn charged(&self) -> u64 {
        self.charged
    }

    /// Read one scalar using the observed fast/slow threshold and raw outcomes.
    pub fn read_u64(&mut self) -> ReadOutcome {
        if self.mode == 1 {
            let Some(next) = self.charged.checked_add(8) else {
                return ReadOutcome::ChargeRejected;
            };
            // Native code stores before comparing to the limit.
            self.charged = next;
            if next > self.limit {
                return ReadOutcome::ChargeRejected;
            }
        }

        if self.remaining.len() > 8 {
            self.read_fast()
        } else {
            self.read_slow()
        }
    }

    fn read_fast(&mut self) -> ReadOutcome {
        let marker = self.remaining[0];
        if marker < 251 {
            self.remaining = &self.remaining[1..];
            return ReadOutcome::Value(u64::from(marker));
        }

        let width = match marker {
            0..=250 => unreachable!("small markers return above"),
            251 => 3,
            252 => 5,
            253 => 9,
            254 => return invalid(4),
            255 => return invalid(12),
        };
        let value = decode_payload(&self.remaining[1..width]);
        self.remaining = &self.remaining[width..];
        ReadOutcome::Value(value)
    }

    fn read_slow(&mut self) -> ReadOutcome {
        let Some((&marker, tail)) = self.remaining.split_first() else {
            return ReadOutcome::NeedMore { additional: 1 };
        };
        // The shared slow helper consumes a present marker before dispatch.
        self.remaining = tail;
        if marker < 251 {
            return ReadOutcome::Value(u64::from(marker));
        }

        let width = match marker {
            0..=250 => unreachable!("small markers return above"),
            251 => 3,
            252 => 5,
            253 => 9,
            254 => return invalid(4),
            255 => return invalid(12),
        };
        let total = tail.len() + 1;
        if total < width {
            return ReadOutcome::NeedMore {
                additional: (width - total) as u64,
            };
        }
        let value = decode_payload(&tail[..width - 1]);
        self.remaining = &tail[width - 1..];
        ReadOutcome::Value(value)
    }
}

const fn invalid(field2: u8) -> ReadOutcome {
    ReadOutcome::Invalid { field1: 5, field2 }
}

fn decode_payload(bytes: &[u8]) -> u64 {
    let mut value = [0; 8];
    value[..bytes.len()].copy_from_slice(bytes);
    u64::from_le_bytes(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn padded(marker: u8) -> [u8; 9] {
        [marker, 1, 2, 3, 4, 5, 6, 7, 8]
    }

    #[test]
    fn raw_tags_match_the_packet_result_layout() {
        assert_eq!(ReadOutcome::Value(0).raw_tag(), 0x12);
        assert_eq!(ReadOutcome::NeedMore { additional: 1 }.raw_tag(), 0x00);
        assert_eq!(ReadOutcome::ChargeRejected.raw_tag(), 0x02);
        assert_eq!(
            ReadOutcome::Invalid {
                field1: 5,
                field2: 4,
            }
            .raw_tag(),
            0x03
        );
    }

    #[test]
    fn fast_route_covers_all_markers_and_consumption() {
        for marker in 0u8..=u8::MAX {
            let input = padded(marker);
            let mut reader = Reader::new(&input, 0, 0, 0);
            let result = reader.read_u64();
            match marker {
                0..=250 => {
                    assert_eq!(result, ReadOutcome::Value(u64::from(marker)));
                    assert_eq!(reader.remaining().len(), 8);
                }
                251 => {
                    assert_eq!(result, ReadOutcome::Value(0x0201));
                    assert_eq!(reader.remaining().len(), 6);
                }
                252 => {
                    assert_eq!(result, ReadOutcome::Value(0x0403_0201));
                    assert_eq!(reader.remaining().len(), 4);
                }
                253 => {
                    assert_eq!(result, ReadOutcome::Value(0x0807_0605_0403_0201));
                    assert!(reader.remaining().is_empty());
                }
                254 => {
                    assert_eq!(
                        result,
                        ReadOutcome::Invalid {
                            field1: 5,
                            field2: 4
                        }
                    );
                    assert_eq!(reader.remaining(), &input);
                }
                255 => {
                    assert_eq!(
                        result,
                        ReadOutcome::Invalid {
                            field1: 5,
                            field2: 12
                        }
                    );
                    assert_eq!(reader.remaining(), &input);
                }
            }
        }
    }

    #[test]
    fn slow_route_grid_matches_marker_width_shortfall_and_consumption_rules() {
        for marker in [0, 250, 251, 252, 253, 254, 255] {
            for total in 0..=8usize {
                let mut input = [0; 8];
                if total > 0 {
                    input[0] = marker;
                    for (i, byte) in input.iter_mut().enumerate().take(total).skip(1) {
                        *byte = i as u8;
                    }
                }
                let mut reader = Reader::new(&input[..total], 0, 0, 0);
                let result = reader.read_u64();
                let consumed = total - reader.remaining().len();
                let (expected, expected_consumed) = if total == 0 {
                    (ReadOutcome::NeedMore { additional: 1 }, 0)
                } else if marker < 251 {
                    (ReadOutcome::Value(u64::from(marker)), 1)
                } else if marker == 254 || marker == 255 {
                    (
                        ReadOutcome::Invalid {
                            field1: 5,
                            field2: if marker == 254 { 4 } else { 12 },
                        },
                        1,
                    )
                } else {
                    let width = match marker {
                        251 => 3,
                        252 => 5,
                        253 => 9,
                        _ => unreachable!(),
                    };
                    if total < width {
                        (
                            ReadOutcome::NeedMore {
                                additional: (width - total) as u64,
                            },
                            1,
                        )
                    } else {
                        let value = decode_payload(&input[1..width]);
                        (ReadOutcome::Value(value), width)
                    }
                };
                assert_eq!(result, expected, "marker={marker}, total={total}");
                assert_eq!(
                    consumed, expected_consumed,
                    "marker={marker}, total={total}"
                );
            }
        }
    }

    #[test]
    fn mode_one_charge_overflow_refuses_without_updating_or_consuming() {
        let input = padded(1);
        let mut reader = Reader::new(&input, 1, u64::MAX, u64::MAX - 7);
        assert_eq!(reader.read_u64(), ReadOutcome::ChargeRejected);
        assert_eq!(reader.charged(), u64::MAX - 7);
        assert_eq!(reader.remaining(), &input);
    }

    #[test]
    fn mode_one_over_limit_refusal_keeps_charge_and_takes_priority() {
        let input = padded(1);
        let mut reader = Reader::new(&input, 1, 7, 8);
        assert_eq!(reader.read_u64(), ReadOutcome::ChargeRejected);
        assert_eq!(reader.charged(), 16);
        assert_eq!(reader.remaining(), &input);
    }

    #[test]
    fn limit_equality_is_allowed_and_other_modes_are_uncharged() {
        let input = padded(3);
        let mut limited = Reader::new(&input, 1, 8, 0);
        assert_eq!(limited.read_u64(), ReadOutcome::Value(3));
        assert_eq!(limited.charged(), 8);

        let mut other_mode = Reader::new(&input, 2, 0, u64::MAX);
        assert_eq!(other_mode.read_u64(), ReadOutcome::Value(3));
        assert_eq!(other_mode.charged(), u64::MAX);
    }

    #[test]
    fn nonminimal_payloads_are_accepted() {
        let input = [251, 1, 0, 0, 0, 0, 0, 0, 0];
        let mut reader = Reader::new(&input, 0, 0, 0);
        assert_eq!(reader.read_u64(), ReadOutcome::Value(1));
        assert_eq!(reader.remaining().len(), 6);
    }

    #[test]
    fn error_fields_match_fast_and_slow_path_while_consumption_differs() {
        let fast_input = padded(254);
        let mut fast = Reader::new(&fast_input, 0, 0, 0);
        assert_eq!(
            fast.read_u64(),
            ReadOutcome::Invalid {
                field1: 5,
                field2: 4
            }
        );
        assert_eq!(fast.remaining().len(), 9);

        let slow_input = [254, 1, 2, 3, 4, 5, 6, 7];
        let mut slow = Reader::new(&slow_input, 0, 0, 0);
        assert_eq!(
            slow.read_u64(),
            ReadOutcome::Invalid {
                field1: 5,
                field2: 4
            }
        );
        assert_eq!(slow.remaining().len(), 7);
    }
}
