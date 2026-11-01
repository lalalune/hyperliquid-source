#![no_std]
#![forbid(unsafe_code)]

pub use hl_bincode_varint::{PayloadOrder, ReaderError};

fn signed_code(code: u8) -> u8 {
    if code < 6 { code + 6 } else { code }
}

fn signed_value(unsigned: u64) -> i64 {
    let magnitude = (unsigned >> 1) as i64;
    let sign = -((unsigned & 1) as i64);
    magnitude ^ sign
}

fn fast_unsigned(input: &mut &[u8], raw_dl: u8) -> Result<u64, ReaderError> {
    let marker = input[0];
    if marker < 251 {
        *input = &input[1..];
        return Ok(u64::from(marker));
    }
    let width = match marker {
        251 => 2,
        252 => 4,
        253 => 8,
        _ => {
            return Err(ReaderError::InvalidIntegerType {
                expected_code: 2,
                found_code: if marker == 254 { 4 } else { 12 },
            });
        }
    };
    let payload = &input[1..1 + width];
    let mut unsigned = 0_u64;
    if raw_dl == 0 {
        for &byte in payload.iter().rev() {
            unsigned = (unsigned << 8) | u64::from(byte);
        }
    } else {
        for &byte in payload {
            unsigned = (unsigned << 8) | u64::from(byte);
        }
    }
    *input = &input[1 + width..];
    Ok(unsigned)
}

/// Complete logical signed64 value/error/cursor projection; not original ABI.
pub fn read_i64(input: &mut &[u8], raw_dl: u8) -> Result<i64, ReaderError> {
    let unsigned = if input.len() > 8 {
        fast_unsigned(input, raw_dl)
    } else {
        let order = if raw_dl == 0 { PayloadOrder::Little } else { PayloadOrder::Big };
        hl_bincode_varint::read_u64(input, order)
    };
    match unsigned {
        Ok(value) => Ok(signed_value(value)),
        Err(ReaderError::InvalidIntegerType { expected_code, found_code }) => {
            Err(ReaderError::InvalidIntegerType {
                expected_code: signed_code(expected_code),
                found_code: signed_code(found_code),
            })
        }
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::{read_i64, ReaderError};
    use std::vec::Vec;

    fn bytes(hex: &str) -> Vec<u8> {
        hex.as_bytes().chunks_exact(2).map(|pair| {
            let text = core::str::from_utf8(pair).unwrap();
            u8::from_str_radix(text, 16).unwrap()
        }).collect()
    }

    #[test]
    fn twenty_first_calls_from_independent_frozen_authority() {
        let mut count = 0;
        for line in include_str!("unit-vectors.tsv").lines() {
            let f: Vec<_> = line.split('|').collect();
            assert_eq!(f.len(), 12);
            let original = bytes(f[2]);
            let mut input = original.as_slice();
            let actual = read_i64(&mut input, f[1].parse().unwrap());
            match f[3] {
                "18" => {
                    let expected: i64 = f[4].parse().unwrap();
                    assert_eq!(actual, Ok(expected), "case {}", f[0]);
                    assert_eq!(expected as u64, u64::from_str_radix(f[5], 16).unwrap());
                }
                "0" => assert_eq!(actual, Err(ReaderError::UnexpectedEnd {
                    needed: f[6].parse().unwrap(),
                }), "case {}", f[0]),
                "3" => assert_eq!(actual, Err(ReaderError::InvalidIntegerType {
                    expected_code: f[7].parse().unwrap(),
                    found_code: f[8].parse().unwrap(),
                }), "case {}", f[0]),
                _ => panic!("invalid frozen active tag"),
            }
            assert_eq!(original.len() - input.len(), f[9].parse::<usize>().unwrap());
            assert_eq!(input.len(), f[10].parse::<usize>().unwrap());
            assert_eq!(input, bytes(f[11]));
            count += 1;
        }
        assert_eq!(count, 20);
    }
}
