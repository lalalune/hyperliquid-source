//! Mode-1 wire/value projection of node94's `EvmKvsMsg` decoder.
//!
//! A batch preserves row order and every byte, including duplicate or empty
//! first arrays. Decoding does not validate state or write to a database.
//! Native enum layout, allocation/growth identity and TLS instrumentation are
//! not reproduced by these independently authored Rust types.

use core::fmt;

use varint::{PayloadOrder, ReaderError};

pub use crate::greeting::reply::ErrorKind;

/// An ordered pair of raw arrays; decoding assigns no database semantics.
pub type Pair = (Box<[u8]>, Box<[u8]>);

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Message {
    Batch(Vec<Pair>),
    End,
}

/// The first rejected cumulative byte count; counts below this are admitted.
pub const TRANSFER_SIZE_LIMIT: u64 = 100_000_000_000;

/// The caller's cumulative count of first-array and second-array bytes.
///
/// This is separate from frame lengths and logical decoder charges. It does
/// not create or apply a database batch, process `End`, or validate state.
#[derive(Debug, Default, Eq, PartialEq)]
pub struct TransferSize {
    total: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransferTooLarge {
    pub total: u64,
}

impl fmt::Display for TransferTooLarge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RocksDb too large")
    }
}

impl std::error::Error for TransferTooLarge {}

impl TransferSize {
    #[must_use]
    pub const fn total(&self) -> u64 {
        self.total
    }

    /// Account for every row before checking the exclusive transfer limit.
    ///
    /// Both additions saturate. Empty arrays and repeated first arrays are
    /// counted normally. An error preserves the updated total; the caller
    /// must abandon the transfer rather than applying the rejected batch.
    pub fn account_batch(&mut self, rows: &[Pair]) -> Result<(), TransferTooLarge> {
        for (first, second) in rows {
            let row_bytes = (first.len() as u64).saturating_add(second.len() as u64);
            self.total = self.total.saturating_add(row_bytes);
        }
        if self.total >= TRANSFER_SIZE_LIMIT {
            Err(TransferTooLarge { total: self.total })
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Decoded {
    pub message: Message,
    pub consumed: usize,
    pub remaining: usize,
    /// Logical charge, distinct from encoded length and physical allocation.
    pub charged: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Failure {
    pub kind: ErrorKind,
    /// Actual cursor progress. The native wrapper's error diagnostic is zero.
    pub consumed: usize,
    pub charged: u64,
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EVM KVS decode at byte {}: {:?}",
            self.consumed, self.kind
        )
    }
}

impl std::error::Error for Failure {}

struct Reader<'a> {
    rest: &'a [u8],
    original_len: usize,
    limit: u64,
    charged: u64,
}

impl Reader<'_> {
    fn failure(&self, kind: ErrorKind) -> Failure {
        Failure {
            kind,
            consumed: self.original_len - self.rest.len(),
            charged: self.charged,
        }
    }

    fn charge(&mut self, amount: u64) -> Result<(), Failure> {
        let next = self
            .charged
            .checked_add(amount)
            .ok_or_else(|| self.failure(ErrorKind::Limit))?;
        self.charged = next;
        if next > self.limit {
            return Err(self.failure(ErrorKind::Limit));
        }
        Ok(())
    }

    fn reader_error(&self, error: ReaderError) -> Failure {
        self.failure(match error {
            ReaderError::UnexpectedEnd { needed } => ErrorKind::UnexpectedEnd {
                needed: needed as u64,
            },
            ReaderError::InvalidIntegerType {
                expected_code,
                found_code,
            } => ErrorKind::InvalidIntegerType {
                expected: expected_code,
                found: found_code,
            },
        })
    }

    fn selector(&mut self) -> Result<u32, Failure> {
        self.charge(4)?;
        if self.rest.len() > 4 && self.rest[0] >= 0xfd {
            return Err(self.failure(ErrorKind::InvalidIntegerType {
                expected: 2,
                found: match self.rest[0] {
                    0xfd => 3,
                    0xfe => 4,
                    _ => 12,
                },
            }));
        }
        let tag = varint::read_u32(&mut self.rest, PayloadOrder::Little)
            .map_err(|error| self.reader_error(error))?;
        if tag > 1 {
            return Err(self.failure(ErrorKind::UnexpectedVariant {
                type_name: "EvmKvsMsg",
                found: tag,
                max: 1,
            }));
        }
        Ok(tag)
    }

    fn length(&mut self) -> Result<u64, Failure> {
        self.charge(8)?;
        if self.rest.len() > 8 {
            let marker = self.rest[0];
            if marker >= 0xfe {
                return Err(self.failure(ErrorKind::InvalidIntegerType {
                    expected: 2,
                    found: if marker == 0xfe { 4 } else { 12 },
                }));
            }
            let decoded = varint::decode_u64_slice_fast(self.rest)
                .expect("more than eight bytes and an admitted u64 marker");
            self.rest = &self.rest[decoded.consumed..];
            Ok(decoded.value)
        } else {
            varint::read_u64(&mut self.rest, PayloadOrder::Little)
                .map_err(|error| self.reader_error(error))
        }
    }

    fn bytes(&mut self) -> Result<Box<[u8]>, Failure> {
        let count = self.length()?;
        self.charge(count)?;
        if count > self.rest.len() as u64 {
            return Err(self.failure(ErrorKind::CollectionTooLong));
        }
        let count = count as usize;
        let bytes = self.rest[..count].into();
        self.rest = &self.rest[count..];
        Ok(bytes)
    }

    fn message(&mut self) -> Result<Message, Failure> {
        if self.selector()? == 1 {
            return Ok(Message::End);
        }
        let count = self.length()?;
        let reservation = count
            .checked_mul(32)
            .ok_or_else(|| self.failure(ErrorKind::Limit))?;
        self.charge(reservation)?;
        let mut rows = Vec::new();
        for _ in 0..count {
            // Each admitted original row owns one reservation, even if its
            // first byte array duplicates an earlier row's first array.
            self.charged -= 32;
            rows.push((self.bytes()?, self.bytes()?));
        }
        Ok(Message::Batch(rows))
    }
}

/// Decode a complete message using mode-1 charging, initially zero.
///
/// Successful decoding may leave a suffix. Errors retain actual cursor and
/// charge progress. Allocation failure follows Rust's allocation behavior;
/// this function does not reproduce the target allocator or native ABI.
pub fn decode(input: &[u8], limit: u64) -> Result<Decoded, Failure> {
    let mut reader = Reader {
        rest: input,
        original_len: input.len(),
        limit,
        charged: 0,
    };
    let message = reader.message()?;
    Ok(Decoded {
        message,
        consumed: input.len() - reader.rest.len(),
        remaining: reader.rest.len(),
        charged: reader.charged,
    })
}

#[cfg(test)]
mod transfer_tests {
    use super::{Pair, TRANSFER_SIZE_LIMIT, TransferSize, TransferTooLarge};

    fn pair(first: &[u8], second: &[u8]) -> Pair {
        (first.into(), second.into())
    }

    // Private counter seeds are synthetic arithmetic controls; no test
    // allocates a 100 GB transfer or constructs an invalid boxed slice.
    #[test]
    fn exclusive_limit_accepts_one_less_and_rejects_equality() {
        let mut size = TransferSize {
            total: TRANSFER_SIZE_LIMIT - 3,
        };
        assert_eq!(size.account_batch(&[pair(&[1], &[2])]), Ok(()));
        assert_eq!(size.total(), TRANSFER_SIZE_LIMIT - 1);
        assert_eq!(
            size.account_batch(&[pair(&[3], &[])]),
            Err(TransferTooLarge {
                total: TRANSFER_SIZE_LIMIT
            })
        );
        assert_eq!(size.total(), TRANSFER_SIZE_LIMIT);
    }

    #[test]
    fn all_rows_are_counted_before_a_limit_error() {
        let mut size = TransferSize {
            total: TRANSFER_SIZE_LIMIT - 1,
        };
        let rows = [pair(&[1], &[]), pair(&[2], &[3]), pair(&[4], &[5, 6])];
        let expected = TRANSFER_SIZE_LIMIT + 5;
        assert_eq!(
            size.account_batch(&rows),
            Err(TransferTooLarge { total: expected })
        );
        assert_eq!(size.total(), expected);
    }

    #[test]
    fn duplicates_and_empty_arrays_are_counted_across_batches() {
        let rows = [pair(b"ab", b"cd"), pair(b"ab", b"x"), pair(&[], &[])];
        let mut size = TransferSize::default();
        assert_eq!(size.total(), 0);
        size.account_batch(&rows).unwrap();
        assert_eq!(size.total(), 7);
        size.account_batch(&rows).unwrap();
        assert_eq!(size.total(), 14);
    }

    #[test]
    fn overflowing_cumulative_count_saturates_and_stays_saturated() {
        let mut size = TransferSize {
            total: u64::MAX - 1,
        };
        let rows = [pair(&[1], &[2]), pair(&[3], &[4])];
        assert_eq!(
            size.account_batch(&rows),
            Err(TransferTooLarge { total: u64::MAX })
        );
        assert_eq!(size.total(), u64::MAX);
    }

    #[test]
    fn an_empty_batch_does_not_reset_a_rejected_total() {
        let mut size = TransferSize {
            total: TRANSFER_SIZE_LIMIT,
        };
        assert_eq!(
            size.account_batch(&[]),
            Err(TransferTooLarge {
                total: TRANSFER_SIZE_LIMIT
            })
        );
        assert_eq!(size.total(), TRANSFER_SIZE_LIMIT);
    }

    #[test]
    fn rejection_text_matches_the_native_message() {
        use std::error::Error;

        let error = TransferTooLarge {
            total: TRANSFER_SIZE_LIMIT,
        };
        assert_eq!(error.to_string(), "RocksDb too large");
        assert!(error.source().is_none());
    }
}
