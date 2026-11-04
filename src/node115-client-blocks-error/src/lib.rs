#![no_std]
//! Complete selected ClientBlocksError logical payload; not its native ABI.
pub use node115_u64_reader_state::Error as ReadError;
use node115_u64_reader_state::Reader;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Value {
    pub index: u32,
    pub fields: Option<[u64; 2]>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Read(ReadError),
    InvalidVariant { index: u32 },
}
#[derive(Debug, PartialEq, Eq)]
pub struct Outcome<'a> {
    pub result: Result<Value, Error>,
    pub remaining: &'a [u8],
    pub charged: u64,
}
// Unchanged MIT logical u32 reader from the existing Request component at base
// 05bc2de303c05525b71e7e257426e741bc66a390; no new reader credit.
fn read_tag(input: &mut &[u8], limit: Option<u64>, charged: &mut u64) -> Result<u32, ReadError> {
    if let Some(limit) = limit {
        let next = charged.checked_add(4).ok_or(ReadError::Limit)?;
        *charged = next;
        if next > limit {
            return Err(ReadError::Limit);
        }
    }
    let source = *input;
    let slow = source.len() <= 4;
    let Some(&marker) = source.first() else {
        return Err(ReadError::UnexpectedEnd { additional: 1 });
    };
    if slow {
        *input = &source[1..];
    }
    if marker < 251 {
        *input = &source[1..];
        return Ok(u32::from(marker));
    }
    let width = match marker {
        251 => 3,
        252 => 5,
        _ => {
            return Err(ReadError::Invalid {
                expected_raw: 2,
                found_raw: match marker {
                    253 => 3,
                    254 => 4,
                    _ => 12,
                },
            });
        }
    };
    if source.len() < width {
        return Err(ReadError::UnexpectedEnd {
            additional: (width - source.len()) as u64,
        });
    }
    let mut bytes = [0; 4];
    bytes[..width - 1].copy_from_slice(&source[1..width]);
    *input = &source[width..];
    Ok(u32::from_le_bytes(bytes))
}

/// Enter where the parent has selected response variant1's Err payload.
/// Decode one prefix, preserving count/cursor on failure; no EOF requirement.
pub fn decode_prefix(mut input: &[u8], limit: Option<u64>, mut charged: u64) -> Outcome<'_> {
    let index = match read_tag(&mut input, limit, &mut charged) {
        Ok(n) => n,
        Err(e) => {
            return Outcome {
                result: Err(Error::Read(e)),
                remaining: input,
                charged,
            };
        }
    };
    if index > 6 {
        return Outcome {
            result: Err(Error::InvalidVariant { index }),
            remaining: input,
            charged,
        };
    }
    if matches!(index, 1 | 5 | 6) {
        let mut reader = Reader::new(input, limit, charged);
        let result = (|| {
            let first = reader.read_u64()?;
            let second = reader.read_u64()?;
            Ok(Value {
                index,
                fields: Some([first, second]),
            })
        })()
        .map_err(Error::Read);
        Outcome {
            result,
            remaining: reader.remaining(),
            charged: reader.charged(),
        }
    } else {
        Outcome {
            result: Ok(Value {
                index,
                fields: None,
            }),
            remaining: input,
            charged,
        }
    }
}
