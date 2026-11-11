//! Selected 20-byte nonce-record field conversion from an already decoded JSON string.
//! This reconstructs the pinned native fixed-width visitor, including whitespace
//! skipping and zero-filled suffixes. It is not a general address validator.
#![no_std]
#![forbid(unsafe_code)]

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Byte length after stripping an optional lowercase `0x` is not forty.
    Length { payload_bytes: usize },
    /// Position is in the decoded input string, including the optional prefix.
    InvalidByte { index: usize, byte: u8 },
}

/// Decode the selected fixed-width field as used by the native nonce record.
///
/// The visitor counts forty input bytes, not forty hexadecimal digits. It skips
/// TAB, LF, CR and SPACE, emits one byte for each pair of digits, and discards
/// an unmatched final nibble. The caller initializes all twenty output bytes
/// to zero; any unfilled suffix remains zero. JSON quoting/unescaping and the
/// surrounding record parser are outside this function.
pub fn decode_key(input: &[u8]) -> Result<[u8; 20], Error> {
    let prefix = usize::from(input.starts_with(b"0x")) * 2;
    let payload = &input[prefix..];
    if payload.len() != 40 {
        return Err(Error::Length {
            payload_bytes: payload.len(),
        });
    }
    let mut output = [0; 20];
    let mut written = 0;
    let mut high = None;
    for (offset, &byte) in payload.iter().enumerate() {
        let nibble = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            b'\t' | b'\n' | b'\r' | b' ' => continue,
            _ => {
                return Err(Error::InvalidByte {
                    index: prefix + offset,
                    byte,
                })
            }
        };
        if let Some(first) = high.take() {
            output[written] = (first << 4) | nibble;
            written += 1;
        } else {
            high = Some(nibble);
        }
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::{decode_key, Error};

    #[test]
    fn exact_bytes_case_and_optional_prefix() {
        let expected = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff, 0x01, 0x23, 0x45, 0x67,
        ];
        assert_eq!(
            decode_key(b"00112233445566778899aabbccddeeff01234567"),
            Ok(expected)
        );
        assert_eq!(
            decode_key(b"0x00112233445566778899AABBCCDDEEFF01234567"),
            Ok(expected)
        );
    }

    #[test]
    fn whitespace_counts_toward_width_but_not_digit_pairs() {
        let mut input = [b' '; 40];
        input[..8].copy_from_slice(b"1\t2\n3\r4 ");
        let mut expected = [0; 20];
        expected[..2].copy_from_slice(&[0x12, 0x34]);
        assert_eq!(decode_key(&input), Ok(expected));
        assert_eq!(decode_key(&[b' '; 40]), Ok([0; 20]));
        input.fill(b' ');
        input[..3].copy_from_slice(b"123");
        expected[1] = 0;
        assert_eq!(decode_key(&input), Ok(expected));
        input.fill(b' ');
        input[0] = b'F';
        assert_eq!(decode_key(&input), Ok([0; 20]));
    }

    #[test]
    fn width_is_checked_before_digits_and_uppercase_prefix_is_not_stripped() {
        assert_eq!(decode_key(b"0x"), Err(Error::Length { payload_bytes: 0 }));
        assert_eq!(
            decode_key(&[b'g'; 39]),
            Err(Error::Length { payload_bytes: 39 })
        );
        assert_eq!(
            decode_key(&[b'0'; 41]),
            Err(Error::Length { payload_bytes: 41 })
        );
        let mut upper = [b'0'; 40];
        upper[1] = b'X';
        assert_eq!(
            decode_key(&upper),
            Err(Error::InvalidByte {
                index: 1,
                byte: b'X'
            })
        );
    }

    #[test]
    fn only_the_four_native_whitespace_bytes_are_accepted() {
        // Each byte is tested in both nibble positions, including after a skip.
        for byte in 0u8..=255 {
            let accepted = byte.is_ascii_hexdigit() || [9, 10, 13, 32].contains(&byte);
            for index in [0, 1, 19, 39] {
                let mut input = [b'0'; 42];
                input[1] = b'x';
                input[index + 2] = byte;
                assert_eq!(
                    decode_key(&input).is_ok(),
                    accepted,
                    "byte {byte} at {index}"
                );
                if !accepted {
                    assert_eq!(
                        decode_key(&input),
                        Err(Error::InvalidByte {
                            index: index + 2,
                            byte
                        })
                    );
                }
            }
        }
        let mut input = [b'0'; 40];
        input[0] = b' ';
        input[39] = b'g';
        assert_eq!(
            decode_key(&input),
            Err(Error::InvalidByte {
                index: 39,
                byte: b'g'
            })
        );
    }
}
