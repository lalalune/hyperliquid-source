#![no_std]
//! Whole logical scalar record reached by Node115 GossipRpcResponse variant2.
//! Field units and original ABI are not recovered; scalar reader is reused MIT.
extern crate node115_u64_reader_state;
pub use node115_u64_reader_state::Error as ReadError;
use node115_u64_reader_state::Reader;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record {
    pub fields: [u64; 4],
    pub optional_value: Option<u64>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Read(ReadError),
    InvalidOption { found: u8 },
}
#[derive(Debug, PartialEq, Eq)]
pub struct Outcome<'a> {
    pub result: Result<Record, Error>,
    pub remaining: &'a [u8],
    pub charged: u64,
}

fn read_fields(reader: &mut Reader<'_>) -> Result<[u64; 4], ReadError> {
    let mut fields = [0; 4];
    for field in &mut fields {
        *field = reader.read_u64()?;
    }
    Ok(fields)
}

/// Decode one prefix. Preserve the native partial cursor/charge on every error.
/// None/Some limit represents canonical unlimited/limited mode; no EOF check.
pub fn decode_prefix(input: &[u8], limit: Option<u64>, charged: u64) -> Outcome<'_> {
    let mut reader = Reader::new(input, limit, charged);
    let fields = match read_fields(&mut reader) {
        Ok(fields) => fields,
        Err(error) => {
            return Outcome {
                result: Err(Error::Read(error)),
                remaining: reader.remaining(),
                charged: reader.charged(),
            };
        }
    };
    let remaining = reader.remaining();
    let mut charged = reader.charged();
    if let Some(limit) = limit {
        let Some(next) = charged.checked_add(1) else {
            return Outcome {
                result: Err(Error::Read(ReadError::Limit)),
                remaining,
                charged,
            };
        };
        // The marker charge is stored before the limit comparison.
        charged = next;
        if next > limit {
            return Outcome {
                result: Err(Error::Read(ReadError::Limit)),
                remaining,
                charged,
            };
        }
    }
    let Some((&marker, rest)) = remaining.split_first() else {
        return Outcome {
            result: Err(Error::Read(ReadError::UnexpectedEnd { additional: 1 })),
            remaining,
            charged,
        };
    };
    match marker {
        0 => Outcome {
            result: Ok(Record {
                fields,
                optional_value: None,
            }),
            remaining: rest,
            charged,
        },
        1 => {
            let mut tail = Reader::new(rest, limit, charged);
            let result = tail
                .read_u64()
                .map(|value| Record {
                    fields,
                    optional_value: Some(value),
                })
                .map_err(Error::Read);
            Outcome {
                result,
                remaining: tail.remaining(),
                charged: tail.charged(),
            }
        }
        // Invalid option markers are consumed too, even with a long suffix.
        found => Outcome {
            result: Err(Error::InvalidOption { found }),
            remaining: rest,
            charged,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn some_prefix_keeps_order_and_suffix() {
        assert_eq!(
            decode_prefix(&[0, 1, 2, 3, 1, 251, 5, 0, 99], Some(41), 0),
            Outcome {
                result: Ok(Record {
                    fields: [0, 1, 2, 3],
                    optional_value: Some(5),
                }),
                remaining: &[99],
                charged: 41,
            }
        );
    }
    #[test]
    fn none_does_not_read_the_suffix() {
        assert_eq!(
            decode_prefix(&[1, 2, 3, 4, 0, 255], None, 91),
            Outcome {
                result: Ok(Record {
                    fields: [1, 2, 3, 4],
                    optional_value: None,
                }),
                remaining: &[255],
                charged: 91,
            }
        );
    }
    #[test]
    fn four_reads_are_not_precharged_together() {
        assert_eq!(
            decode_prefix(&[0, 0, 0, 0, 0], Some(7), 0),
            Outcome {
                result: Err(Error::Read(ReadError::Limit)),
                remaining: &[0, 0, 0, 0, 0],
                charged: 8,
            }
        );
    }
    #[test]
    fn marker_charge_commits_before_limit_and_empty_check() {
        assert_eq!(
            decode_prefix(&[0, 0, 0, 0, 0], Some(32), 0),
            Outcome {
                result: Err(Error::Read(ReadError::Limit)),
                remaining: &[0],
                charged: 33,
            }
        );
        assert_eq!(
            decode_prefix(&[0, 0, 0, 0], Some(33), 0),
            Outcome {
                result: Err(Error::Read(ReadError::UnexpectedEnd { additional: 1 })),
                remaining: &[],
                charged: 33,
            }
        );
    }
    #[test]
    fn invalid_marker_consumes_one_even_with_long_suffix() {
        let input = [0, 0, 0, 0, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
        assert_eq!(
            decode_prefix(&input, Some(100), 0),
            Outcome {
                result: Err(Error::InvalidOption { found: 2 }),
                remaining: &input[5..],
                charged: 33,
            }
        );
    }
    #[test]
    fn optional_read_refusal_preserves_consumed_marker() {
        assert_eq!(
            decode_prefix(&[0, 0, 0, 0, 1, 9], Some(40), 0),
            Outcome {
                result: Err(Error::Read(ReadError::Limit)),
                remaining: &[9],
                charged: 41,
            }
        );
    }
    #[test]
    fn marker_count_overflow_does_not_consume_it() {
        assert_eq!(
            decode_prefix(&[0, 0, 0, 0, 0], Some(u64::MAX), u64::MAX - 32),
            Outcome {
                result: Err(Error::Read(ReadError::Limit)),
                remaining: &[0],
                charged: u64::MAX,
            }
        );
    }
}
