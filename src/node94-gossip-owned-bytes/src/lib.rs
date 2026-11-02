//! Qualified normal-return projection of node94's validated owned-byte helper.
//!
//! The real allocation/copy/drop domain and inactive-output exclusions are in
//! README.md. These safe representations do not recover the native type/ABI.

#![forbid(unsafe_code)]

use hl_bincode_varint::{DecodeError, PayloadOrder, ReaderError};

const _: () = assert!(usize::BITS == 64);

/// First failing sequence and its optional present invalid-prefix length.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Utf8Fault {
    pub valid_up_to: usize,
    pub error_len: Option<u8>,
}

/// Validate shortest UTF-8 encodings of Unicode scalar values.
///
/// Incomplete suffixes have no error length. A present bad continuation has
/// length 1/2/3 according to its position; an illegal lead has length 1.
pub fn validate_bytes(bytes: &[u8]) -> Result<(), Utf8Fault> {
    let mut start = 0;
    while start < bytes.len() {
        let lead = bytes[start];
        if lead < 0x80 {
            start += 1;
            continue;
        }
        let width = match lead {
            0xc2..=0xdf => 2,
            0xe0..=0xef => 3,
            0xf0..=0xf4 => 4,
            _ => return Err(Utf8Fault { valid_up_to: start, error_len: Some(1) }),
        };
        for offset in 1..width {
            let Some(&next) = bytes.get(start + offset) else {
                return Err(Utf8Fault { valid_up_to: start, error_len: None });
            };
            let valid = if offset == 1 {
                match lead {
                    0xe0 => (0xa0..=0xbf).contains(&next),
                    0xed => (0x80..=0x9f).contains(&next),
                    0xf0 => (0x90..=0xbf).contains(&next),
                    0xf4 => (0x80..=0x8f).contains(&next),
                    _ => (0x80..=0xbf).contains(&next),
                }
            } else {
                (0x80..=0xbf).contains(&next)
            };
            if !valid {
                return Err(Utf8Fault {
                    valid_up_to: start,
                    error_len: Some(offset as u8),
                });
            }
        }
        start += width;
    }
    Ok(())
}

/// Chosen representation of observed raw state words, not a native layout.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Budget {
    pub mode_word: u64,
    pub counter: u64,
    pub limit: u64,
}

/// Actual counter assignments made by one invocation, including +0 stores.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CounterStores {
    values: [u64; 2],
    len: u8,
}

impl CounterStores {
    pub fn as_slice(&self) -> &[u64] {
        &self.values[..usize::from(self.len)]
    }

    fn assign(&mut self, budget: &mut Budget, value: u64) {
        budget.counter = value;
        self.values[usize::from(self.len)] = value;
        self.len += 1;
    }
}

/// Established header fields, with independently chosen source names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeaderFault {
    Budget,
    Need { additional: usize },
    Type { expected: u8, found: u8 },
}

/// Pipeline stages preserve the native distinction between its error routes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Failure {
    Header(HeaderFault),
    PayloadBudget,
    PayloadUnavailable,
    InvalidUtf8(Utf8Fault),
}

/// Owned bytes whose complete content has passed this component's validator.
#[derive(Debug, Eq, PartialEq)]
pub struct ValidatedBytes(Vec<u8>);

impl ValidatedBytes {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

/// A chosen logical result/store/release-request projection.
#[derive(Debug, Eq, PartialEq)]
pub struct Outcome {
    pub result: Result<ValidatedBytes, Failure>,
    pub counter_stores: CounterStores,
    /// Present only after dropping the newly allocated invalid UTF-8 buffer.
    /// This records a release request, not original allocator/cache behavior.
    pub release_request_length: Option<u64>,
}

fn header(
    input: &mut &[u8],
    budget: &mut Budget,
    stores: &mut CounterStores,
) -> Result<u64, HeaderFault> {
    if budget.mode_word as u32 == 1 {
        let Some(next) = budget.counter.checked_add(8) else {
            return Err(HeaderFault::Budget);
        };
        stores.assign(budget, next);
        if next > budget.limit {
            return Err(HeaderFault::Budget);
        }
    }
    if input.len() > 8 {
        match hl_bincode_varint::decode_u64_slice_fast(input) {
            Ok(decoded) => {
                *input = &input[decoded.consumed..];
                Ok(decoded.value)
            }
            Err(DecodeError::RejectedMarker { marker }) => {
                let found = match marker {
                    0xfe => 4,
                    0xff => 12,
                    _ => unreachable!("unchanged accepted fast decoder rejects only FE/FF"),
                };
                Err(HeaderFault::Type { expected: 2, found })
            }
            Err(DecodeError::FastPathUnavailable { .. }) => {
                unreachable!("the accepted fast decoder is called only with more than8 bytes")
            }
        }
    } else {
        hl_bincode_varint::read_u64(input, PayloadOrder::Little).map_err(|error| match error {
            ReaderError::UnexpectedEnd { needed } => HeaderFault::Need { additional: needed },
            ReaderError::InvalidIntegerType { expected_code, found_code } => {
                HeaderFault::Type { expected: expected_code, found: found_code }
            }
        })
    }
}

/// Decode an owned length-delimited UTF-8 byte buffer under the normal domain.
///
/// The complete raw mode QWORD enables payload charging when nonzero; its low
/// DWORD enables the header's charge only when exactly1. Counter assignments
/// precede their limit comparisons. Payload is consumed after real copy and
/// before validation; validation error drops the copied buffer before returning.
pub fn decode_owned_bytes(input: &mut &[u8], budget: &mut Budget) -> Outcome {
    let mut stores = CounterStores::default();
    let length = match header(input, budget, &mut stores) {
        Ok(length) => length,
        Err(problem) => {
            return Outcome {
                result: Err(Failure::Header(problem)),
                counter_stores: stores,
                release_request_length: None,
            };
        }
    };
    if budget.mode_word != 0 {
        let Some(next) = budget.counter.checked_add(length) else {
            return Outcome {
                result: Err(Failure::PayloadBudget),
                counter_stores: stores,
                release_request_length: None,
            };
        };
        stores.assign(budget, next);
        if next > budget.limit {
            return Outcome {
                result: Err(Failure::PayloadBudget),
                counter_stores: stores,
                release_request_length: None,
            };
        }
    }
    if length > input.len() as u64 {
        return Outcome {
            result: Err(Failure::PayloadUnavailable),
            counter_stores: stores,
            release_request_length: None,
        };
    }
    // Availability proves length<=remaining<=isize::MAX before allocation.
    let count = length as usize;
    let after_header = *input;
    let owned = if count == 0 { Vec::new() } else { after_header[..count].to_vec() };
    *input = &after_header[count..];
    let result = match validate_bytes(&owned) {
        Ok(()) => Ok(ValidatedBytes(owned)),
        Err(problem) => {
            drop(owned);
            return Outcome {
                result: Err(Failure::InvalidUtf8(problem)),
                counter_stores: stores,
                release_request_length: Some(length),
            };
        }
    };
    Outcome { result, counter_stores: stores, release_request_length: None }
}
