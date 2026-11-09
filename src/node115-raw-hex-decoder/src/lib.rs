//! Value-level model of the node #115 hex decoder at VA `0x167afd0`.
//!
//! Input is the already-extracted string byte slice. This does not parse JSON,
//! reproduce native allocation/error objects, or claim transaction validity.

/// Observed validation failures, without assigning recovered native error names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeError {
    /// The original slice length is odd; this check precedes prefix stripping.
    OddLength,
    /// First invalid byte, indexed after stripping an initial lowercase `0x`.
    InvalidByte { index: usize, byte: u8 },
}

fn nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

/// Decode the observed string-derived byte slice into bytes.
///
/// Checks odd length before removing a lowercase `0x` prefix. Uppercase `0X`
/// is not a prefix. Invalid digits are reported in order, with indexes relative
/// to the post-prefix slice. Empty and prefix-only slices decode to empty bytes.
pub fn decode_hex(input: &[u8]) -> Result<Vec<u8>, DecodeError> {
    if input.len() & 1 != 0 {
        return Err(DecodeError::OddLength);
    }

    let digits = input.strip_prefix(b"0x").unwrap_or(input);
    let mut decoded = Vec::with_capacity(digits.len() / 2);
    for (index, pair) in digits.chunks_exact(2).enumerate() {
        let high = nibble(pair[0]).ok_or(DecodeError::InvalidByte {
            index: index * 2,
            byte: pair[0],
        })?;
        let low = nibble(pair[1]).ok_or(DecodeError::InvalidByte {
            index: index * 2 + 1,
            byte: pair[1],
        })?;
        decoded.push((high << 4) | low);
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::{decode_hex, nibble, DecodeError};

    #[test]
    fn matches_all_256_binary_table_entries() {
        let rows = include_str!(
            "../../../research/work-items/RE-011-evm-raw-forward-115/hex-characters.tsv"
        );
        let mut count = 0;
        for row in rows.lines().skip(1) {
            let mut fields = row.split('\t');
            let byte = u8::from_str_radix(fields.next().unwrap(), 16).unwrap();
            let expected = fields.next().unwrap();
            assert!(fields.next().unwrap() == if expected == "-" { "0" } else { "1" });
            let _vector_lane_mask = fields.next().unwrap();
            let actual = nibble(byte)
                .map(|n| n.to_string())
                .unwrap_or_else(|| "-".into());
            assert_eq!(actual, expected, "byte={byte:#04x}");
            count += 1;
        }
        assert_eq!(count, 256);
    }

    #[test]
    fn matches_static_decoder_cases() {
        let rows =
            include_str!("../../../research/work-items/RE-011-evm-raw-forward-115/hex-cases.tsv");
        let mut count = 0;
        for row in rows.lines().skip(1) {
            let mut fields = row.split('\t');
            let case = fields.next().unwrap();
            let input = hex_bytes(fields.next().unwrap());
            let _input_len: usize = fields.next().unwrap().parse().unwrap();
            let status = fields.next().unwrap();
            let result = fields.next().unwrap();
            let invalid_byte = fields.next().unwrap();
            let actual = decode_hex(&input);
            match status {
                "ok" => assert_eq!(actual.unwrap(), hex_bytes(result), "case={case}"),
                "odd" => assert_eq!(actual, Err(DecodeError::OddLength), "case={case}"),
                "invalid" => assert_eq!(
                    actual,
                    Err(DecodeError::InvalidByte {
                        index: result.parse().unwrap(),
                        byte: u8::from_str_radix(invalid_byte, 16).unwrap(),
                    }),
                    "case={case}"
                ),
                other => panic!("unknown packet status {other} in {case}"),
            }
            count += 1;
        }
        assert_eq!(count, 17);
    }

    fn hex_bytes(value: &str) -> Vec<u8> {
        assert_eq!(value.len() % 2, 0);
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let hi = (pair[0] as char).to_digit(16).unwrap() as u8;
                let lo = (pair[1] as char).to_digit(16).unwrap() as u8;
                hi * 16 + lo
            })
            .collect()
    }

    #[test]
    fn checks_length_before_prefix_and_reports_post_prefix_index() {
        assert_eq!(decode_hex(b"0x0"), Err(DecodeError::OddLength));
        assert_eq!(decode_hex(b"z"), Err(DecodeError::OddLength));
        assert_eq!(
            decode_hex(b"0X"),
            Err(DecodeError::InvalidByte {
                index: 1,
                byte: b'X'
            })
        );
        assert_eq!(
            decode_hex(b"0xzz"),
            Err(DecodeError::InvalidByte {
                index: 0,
                byte: b'z'
            })
        );
        assert_eq!(decode_hex(b""), Ok(vec![]));
        assert_eq!(decode_hex(b"0x"), Ok(vec![]));
    }

    #[test]
    fn checks_every_possible_two_byte_slice() {
        for high_byte in 0u8..=u8::MAX {
            for low_byte in 0u8..=u8::MAX {
                let input = [high_byte, low_byte];
                let expected = if input == *b"0x" {
                    Ok(vec![])
                } else {
                    match (nibble(high_byte), nibble(low_byte)) {
                        (Some(high), Some(low)) => Ok(vec![(high << 4) | low]),
                        (None, _) => Err(DecodeError::InvalidByte {
                            index: 0,
                            byte: high_byte,
                        }),
                        (Some(_), None) => Err(DecodeError::InvalidByte {
                            index: 1,
                            byte: low_byte,
                        }),
                    }
                };
                assert_eq!(decode_hex(&input), expected, "input={input:02x?}");
            }
        }
    }
}
