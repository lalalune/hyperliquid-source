#![no_std]
//! Whole logical record from node115 0x5968840 and its fixed-copy helper.
pub use node115_u64_reader_state::Error;
use node115_u64_reader_state::Reader;

/// Field names/units and original Rust layout remain unknown. Wire order is
/// fields[0], fields[1], then exactly 2048 uninterpreted bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub bytes: [u8; 2048],
    pub fields: [u64; 2],
}

#[derive(Debug, PartialEq, Eq)]
pub struct Outcome<'a> {
    pub result: Result<Record, Error>,
    pub remaining: &'a [u8],
    pub charged: u64,
}

fn field(reader: &mut Reader<'_>) -> Result<u64, Error> {
    // This sibling uses identical logical scalar/cursor/charge rules, but its
    // actual error-constructor argument is 5 on both fast and slow routes.
    reader.read_u64().map_err(|error| match error {
        Error::Invalid { found_raw, .. } => Error::Invalid {
            expected_raw: 5,
            found_raw,
        },
        other => other,
    })
}

/// Decode one prefix, retaining every established partial cursor/count effect.
/// None/Some represents canonical mode0/mode1, not all possible raw mode words.
/// The safe Result/owned byte array is not the native output-buffer ABI.
pub fn decode_prefix(input: &[u8], limit: Option<u64>, charged: u64) -> Outcome<'_> {
    let mut reader = Reader::new(input, limit, charged);
    let mut fields = [0; 2];
    for value in &mut fields {
        match field(&mut reader) {
            Ok(v) => *value = v,
            Err(error) => {
                return Outcome {
                    result: Err(error),
                    remaining: reader.remaining(),
                    charged: reader.charged(),
                };
            }
        }
    }
    let remaining = reader.remaining();
    let mut charged = reader.charged();
    if let Some(limit) = limit {
        let Some(next) = charged.checked_add(2048) else {
            return Outcome {
                result: Err(Error::Limit),
                remaining,
                charged,
            };
        };
        charged = next;
        if next > limit {
            return Outcome {
                result: Err(Error::Limit),
                remaining,
                charged,
            };
        }
    }
    if remaining.len() < 2048 {
        return Outcome {
            result: Err(Error::UnexpectedEnd {
                additional: (2048 - remaining.len()) as u64,
            }),
            remaining,
            charged,
        };
    }
    let mut bytes = [0; 2048];
    bytes.copy_from_slice(&remaining[..2048]);
    Outcome {
        result: Ok(Record { bytes, fields }),
        remaining: &remaining[2048..],
        charged,
    }
}
