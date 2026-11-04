#![no_std]
//! Logical signed-scalar relation of the two pinned Node115 readers.
//! This is not the original result-union ABI or the caller's budget policy.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeError {
    Shortfall { additional: usize },
    UnexpectedType { expected: u8, actual: u8 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Cursor<'a> {
    remaining: &'a [u8],
}

impl<'a> Cursor<'a> {
    pub const fn new(input: &'a [u8]) -> Self {
        Self { remaining: input }
    }

    pub const fn remaining(&self) -> &'a [u8] {
        self.remaining
    }

    /// Zero selects little endian; every other byte selects big endian.
    ///
    /// With fewer than nine available bytes, the native slow reader consumes
    /// the marker before rejecting a type or reporting a missing payload.
    /// The fast reader rejects unsupported markers without consuming them.
    /// Its expected-type diagnostic is 8, while the slow path reports 9.
    pub fn read_signed(&mut self, endian: u8) -> Result<i64, DecodeError> {
        let input = self.remaining;
        let Some(&marker) = input.first() else {
            return Err(DecodeError::Shortfall { additional: 1 });
        };
        let fast = input.len() >= 9;
        if !fast {
            self.remaining = &input[1..];
        }
        let payload_len = match marker {
            0..=250 => 0,
            251 => 2,
            252 => 4,
            253 => 8,
            _ => {
                return Err(DecodeError::UnexpectedType {
                    expected: if fast { 8 } else { 9 },
                    actual: if marker == 254 { 10 } else { 12 },
                });
            }
        };
        let needed = 1 + payload_len;
        if input.len() < needed {
            return Err(DecodeError::Shortfall {
                additional: needed - input.len(),
            });
        }
        let unsigned = if payload_len == 0 {
            u64::from(marker)
        } else {
            let mut bytes = [0_u8; 8];
            if endian == 0 {
                bytes[..payload_len].copy_from_slice(&input[1..needed]);
                u64::from_le_bytes(bytes)
            } else {
                bytes[8 - payload_len..].copy_from_slice(&input[1..needed]);
                u64::from_be_bytes(bytes)
            }
        };
        self.remaining = &input[needed..];
        Ok(((unsigned >> 1) as i64) ^ -((unsigned & 1) as i64))
    }
}

#[cfg(test)]
mod tests {
    use super::{Cursor, DecodeError};

    #[test]
    fn inline_values_and_the_unread_suffix() {
        for byte in 0_u8..=250 {
            // Signed values alternate 0,-1,1,-2,...,125.
            let expected = if byte % 2 == 0 {
                i64::from(byte / 2)
            } else {
                -i64::from(byte / 2) - 1
            };
            for suffix_len in [0, 7, 8, 9] {
                let mut input = [0xa5; 10];
                input[0] = byte;
                let mut cursor = Cursor::new(&input[..1 + suffix_len]);
                assert_eq!(cursor.read_signed(0), Ok(expected));
                assert_eq!(cursor.remaining(), &input[1..1 + suffix_len]);
            }
        }
    }

    #[test]
    fn native_marker_widths_and_byte_order() {
        let rows: &[(&[u8], u8, i64)] = &[
            (&[251, 0x34, 0x12], 0, 2330),
            (&[251, 0x12, 0x34], 1, 2330),
            (&[251, 0x12, 0x35], 255, -2331),
            (&[252, 0x78, 0x56, 0x34, 0x12], 0, 152709948),
            (&[252, 0x12, 0x34, 0x56, 0x79], 2, -152709949),
            (
                &[253, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
                0,
                i64::MAX,
            ),
            (
                &[253, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
                0,
                i64::MIN,
            ),
            (&[253, 0x80, 0, 0, 0, 0, 0, 0, 1], 255, -4611686018427387905),
        ];
        for &(input, endian, expected) in rows {
            let mut cursor = Cursor::new(input);
            assert_eq!(cursor.read_signed(endian), Ok(expected), "{input:?}");
            assert!(cursor.remaining().is_empty());
        }
    }

    #[test]
    fn nonminimal_payloads_are_accepted_on_fast_and_short_paths() {
        for marker in [251, 252, 253] {
            let payload_len = match marker {
                251 => 2,
                252 => 4,
                _ => 8,
            };
            for endian in [0, 1, 255] {
                for length in [1 + payload_len, 9, 12] {
                    let mut input = [0_u8; 12];
                    input[0] = marker;
                    input[1 + payload_len..].fill(0xa5);
                    let mut cursor = Cursor::new(&input[..length]);
                    assert_eq!(cursor.read_signed(endian), Ok(0));
                    assert_eq!(cursor.remaining(), &input[1 + payload_len..length]);
                }
            }
        }
    }

    #[test]
    fn shortfall_consumes_only_the_available_marker() {
        let mut empty = Cursor::new(&[]);
        assert_eq!(
            empty.read_signed(0),
            Err(DecodeError::Shortfall { additional: 1 })
        );
        assert_eq!(empty.remaining(), &[]);
        for (marker, payload_len) in [(251, 2), (252, 4), (253, 8)] {
            let mut input = [0x7b; 9];
            input[0] = marker;
            for length in 1..1 + payload_len {
                let mut cursor = Cursor::new(&input[..length]);
                assert_eq!(
                    cursor.read_signed(255),
                    Err(DecodeError::Shortfall {
                        additional: 1 + payload_len - length
                    })
                );
                assert_eq!(cursor.remaining(), &input[1..length]);
            }
        }
    }

    #[test]
    fn unsupported_marker_diagnostics_and_consumption_depend_on_path() {
        for (marker, actual) in [(254, 10), (255, 12)] {
            let mut input = [0x7b; 12];
            input[0] = marker;
            for length in 1..=12 {
                let mut cursor = Cursor::new(&input[..length]);
                assert_eq!(
                    cursor.read_signed(0),
                    Err(DecodeError::UnexpectedType {
                        expected: if length >= 9 { 8 } else { 9 },
                        actual
                    })
                );
                let consumed = usize::from(length < 9);
                assert_eq!(cursor.remaining(), &input[consumed..length]);
            }
        }
    }

    #[test]
    fn sequential_values_retain_the_failed_values_payload() {
        let input = [1, 251, 2, 0, 253, 0xa5, 0x5a];
        let mut cursor = Cursor::new(&input);
        assert_eq!(cursor.read_signed(0), Ok(-1));
        assert_eq!(cursor.read_signed(0), Ok(1));
        assert_eq!(
            cursor.read_signed(0),
            Err(DecodeError::Shortfall { additional: 6 })
        );
        assert_eq!(cursor.remaining(), &[0xa5, 0x5a]);
    }
}
