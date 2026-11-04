//! Selected node115 response-v2 envelope. No native ABI or full response claim.
#![no_std]
use node115_gossip_response_record as record;
pub use node115_gossip_response_record::{ReadError, Record};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Selection {
    Variant2(Option<Record>),
    OtherVariant(u32),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Read(ReadError),
    InvalidVariant { index: u32 },
    InvalidOuterOption { found: u8 },
    Record(record::Error),
}
#[derive(Debug, PartialEq, Eq)]
pub struct Outcome<'a> {
    pub result: Result<Selection, Error>,
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

/// Decode the complete variant2 envelope or report the unimplemented selection
/// boundary for variants0/1. OtherVariant is not a decoded full response.
pub fn decode_prefix(mut input: &[u8], limit: Option<u64>, mut charged: u64) -> Outcome<'_> {
    let kind = match read_tag(&mut input, limit, &mut charged) {
        Ok(v) => v,
        Err(e) => {
            return Outcome {
                result: Err(Error::Read(e)),
                remaining: input,
                charged,
            };
        }
    };
    if kind < 2 {
        return Outcome {
            result: Ok(Selection::OtherVariant(kind)),
            remaining: input,
            charged,
        };
    }
    if kind > 2 {
        return Outcome {
            result: Err(Error::InvalidVariant { index: kind }),
            remaining: input,
            charged,
        };
    }
    if let Some(limit) = limit {
        let Some(next) = charged.checked_add(1) else {
            return Outcome {
                result: Err(Error::Read(ReadError::Limit)),
                remaining: input,
                charged,
            };
        };
        charged = next;
        if next > limit {
            return Outcome {
                result: Err(Error::Read(ReadError::Limit)),
                remaining: input,
                charged,
            };
        }
    }
    let Some((&marker, rest)) = input.split_first() else {
        return Outcome {
            result: Err(Error::Read(ReadError::UnexpectedEnd { additional: 1 })),
            remaining: input,
            charged,
        };
    };
    match marker {
        0 => Outcome {
            result: Ok(Selection::Variant2(None)),
            remaining: rest,
            charged,
        },
        1 => {
            let child = record::decode_prefix(rest, limit, charged);
            Outcome {
                result: child
                    .result
                    .map(|r| Selection::Variant2(Some(r)))
                    .map_err(Error::Record),
                remaining: child.remaining,
                charged: child.charged,
            }
        }
        found => Outcome {
            result: Err(Error::InvalidOuterOption { found }),
            remaining: rest,
            charged,
        },
    }
}
