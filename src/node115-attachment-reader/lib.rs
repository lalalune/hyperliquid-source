//! Selected node115 attachment vector, with native scalar budget/cursor rules.
//! Valid reader modes and successful allocation are premises. This is not the
//! surrounding ClientBlock header, outer transport or captured async ABI.
use node115_u64_reader_state::{Error as ScalarError, Reader as ScalarReader};
use std::sync::Arc;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attachment {
    pub id: [u8; 32],
    pub bytes: Arc<[u8]>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Scalar(ScalarError),
    Limit,
    HashTruncated { additional: u64 },
    BlobTruncated { declared: u64, available: u64 },
}

/// The same logical input and charged state is threaded through all children.
/// `charged` measures the recovered typed-reader accounting, not bytes read.
pub struct Reader<'a> {
    remaining: &'a [u8],
    limit: Option<u64>,
    charged: u64,
}

impl<'a> Reader<'a> {
    pub fn new(input: &'a [u8], limit: Option<u64>, charged: u64) -> Self {
        Self {
            remaining: input,
            limit,
            charged,
        }
    }
    pub fn remaining(&self) -> &'a [u8] {
        self.remaining
    }
    pub fn charged(&self) -> u64 {
        self.charged
    }

    fn count(&mut self) -> Result<u64, Error> {
        let mut scalar = ScalarReader::new(self.remaining, self.limit, self.charged);
        let result = scalar.read_u64();
        // Commit both fields even on errors, exactly as the reused reader does.
        self.remaining = scalar.remaining();
        self.charged = scalar.charged();
        result.map_err(Error::Scalar)
    }

    fn charge(&mut self, amount: u64) -> Result<(), Error> {
        if let Some(limit) = self.limit {
            // Overflow leaves the old value; exceeding the limit stores the sum.
            let sum = self.charged.checked_add(amount).ok_or(Error::Limit)?;
            self.charged = sum;
            if sum > limit {
                return Err(Error::Limit);
            }
        }
        Ok(())
    }

    fn attachment(&mut self) -> Result<Attachment, Error> {
        self.charge(32)?;
        if self.remaining.len() < 32 {
            return Err(Error::HashTruncated {
                additional: 32 - self.remaining.len() as u64,
            });
        }
        let (id, rest) = self.remaining.split_at(32);
        let id = id.try_into().expect("exactly 32 bytes");
        self.remaining = rest;
        let length = self.count()?;
        self.charge(length)?;
        if length > self.remaining.len() as u64 {
            return Err(Error::BlobTruncated {
                declared: length,
                available: self.remaining.len() as u64,
            });
        }
        let (payload, rest) = self.remaining.split_at(length as usize);
        let bytes = Arc::from(payload);
        self.remaining = rest;
        Ok(Attachment { id, bytes })
    }

    /// Decode the vector at the current cursor. On failure no completed rows
    /// escape; owned prefix rows are dropped, while cursor/charges stay committed.
    pub fn read_attachments(&mut self) -> Result<Vec<Attachment>, Error> {
        let count = self.count()?;
        if self.limit.is_some() {
            let reservation = count.checked_mul(40).ok_or(Error::Limit)?;
            self.charge(reservation)?;
        }
        let mut rows = Vec::new();
        for _ in 0..count {
            if self.limit.is_some() {
                // The accepted reservation includes 40 for each unvisited row.
                self.charged = self
                    .charged
                    .checked_sub(40)
                    .expect("accepted per-row reservation");
            }
            rows.push(self.attachment()?);
        }
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn one(length: u8, supplied: &[u8]) -> Vec<u8> {
        let mut input = vec![1];
        input.extend([0x42; 32]);
        input.push(length);
        input.extend(supplied);
        input
    }

    #[test]
    fn exact_budget_and_unlimited_preserve_trailing_input() {
        let mut input = one(3, &[9, 8, 7]);
        input.push(0xee);
        for (limit, initial, expected_charge) in [(Some(51), 0, 51), (None, 91, 91)] {
            let mut reader = Reader::new(&input, limit, initial);
            let rows = reader.read_attachments().unwrap();
            assert_eq!(
                rows,
                vec![Attachment {
                    id: [0x42; 32],
                    bytes: Arc::from([9, 8, 7])
                }]
            );
            assert_eq!(reader.remaining(), &[0xee]);
            assert_eq!(reader.charged(), expected_charge);
        }
        let mut empty = Reader::new(&[0, 0xee], Some(8), 0);
        assert!(empty.read_attachments().unwrap().is_empty());
        assert_eq!((empty.remaining(), empty.charged()), (&[0xee][..], 8));
    }

    #[test]
    fn equal_ids_preserve_both_rows_and_wire_order() {
        let mut input = one(0, &[]);
        input[0] = 2;
        input.extend([0x42; 32]);
        input.extend([3, 9, 8, 7, 0xee]);
        let mut reader = Reader::new(&input, Some(91), 0);
        let rows = reader.read_attachments().unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].id, rows[1].id);
        assert!(rows[0].bytes.is_empty());
        assert_eq!(&*rows[1].bytes, &[9, 8, 7]);
        assert_eq!((reader.remaining(), reader.charged()), (&[0xee][..], 91));
    }

    #[test]
    fn each_nested_failure_keeps_its_native_cursor_and_charge() {
        // Expected positions and charges were calculated from the retained
        // native call/charge order, independently of this implementation.
        let mut partial_id = vec![1];
        partial_id.extend([0x42; 31]);
        let mut no_length = vec![1];
        no_length.extend([0x42; 32]);
        let mut second_hash_missing = one(1, &[0x77]);
        second_hash_missing[0] = 2;
        let mut second_blob_missing = second_hash_missing.clone();
        second_blob_missing.extend([0x33; 32]);
        second_blob_missing.push(3);
        let mut invalid_length = vec![1];
        invalid_length.extend([0x42; 32]);
        invalid_length.push(254);
        let cases = [
            (
                invalid_length,
                Error::Scalar(ScalarError::Invalid {
                    expected_raw: 3,
                    found_raw: 4,
                }),
                34,
                48,
            ),
            (
                vec![],
                Error::Scalar(ScalarError::UnexpectedEnd { additional: 1 }),
                0,
                8,
            ),
            (vec![1], Error::HashTruncated { additional: 32 }, 1, 40),
            (partial_id, Error::HashTruncated { additional: 1 }, 1, 40),
            (
                no_length,
                Error::Scalar(ScalarError::UnexpectedEnd { additional: 1 }),
                33,
                48,
            ),
            (
                one(3, &[]),
                Error::BlobTruncated {
                    declared: 3,
                    available: 0,
                },
                34,
                51,
            ),
            (
                one(3, &[4, 5]),
                Error::BlobTruncated {
                    declared: 3,
                    available: 2,
                },
                34,
                51,
            ),
            (
                second_hash_missing,
                Error::HashTruncated { additional: 32 },
                35,
                81,
            ),
            (
                second_blob_missing,
                Error::BlobTruncated {
                    declared: 3,
                    available: 0,
                },
                68,
                92,
            ),
        ];
        for (input, error, consumed, charge) in cases {
            let mut reader = Reader::new(&input, Some(1000), 0);
            assert_eq!(reader.read_attachments(), Err(error));
            assert_eq!(input.len() - reader.remaining().len(), consumed);
            assert_eq!(reader.charged(), charge);
        }
    }

    #[test]
    fn invalid_length_preserves_scalar_fast_and_slow_error_distinction() {
        for (padding, expected_raw, consumed) in [(0, 3, 34), (8, 2, 33)] {
            let mut input = vec![1];
            input.extend([0x42; 32]);
            input.push(254);
            input.extend(vec![0; padding]);
            let mut reader = Reader::new(&input, Some(1000), 0);
            assert_eq!(
                reader.read_attachments(),
                Err(Error::Scalar(ScalarError::Invalid {
                    expected_raw,
                    found_raw: 4
                }))
            );
            assert_eq!(input.len() - reader.remaining().len(), consumed);
            assert_eq!(reader.charged(), 48);
        }
    }

    #[test]
    fn precharge_overflow_and_late_blob_limit_have_different_commits() {
        let mut huge = vec![253];
        huge.extend(u64::MAX.to_le_bytes());
        let cases = [
            (vec![1], Some(7), 0, Error::Scalar(ScalarError::Limit), 0, 8),
            (vec![2], Some(87), 0, Error::Limit, 1, 88),
            (one(3, &[9, 8, 7]), Some(50), 0, Error::Limit, 34, 51),
            (huge.clone(), Some(u64::MAX), 0, Error::Limit, 9, 8),
            (
                vec![1],
                Some(u64::MAX),
                u64::MAX - 20,
                Error::Limit,
                1,
                u64::MAX - 12,
            ),
            (
                vec![1],
                Some(u64::MAX),
                u64::MAX - 7,
                Error::Scalar(ScalarError::Limit),
                0,
                u64::MAX - 7,
            ),
            (huge, None, 5, Error::HashTruncated { additional: 32 }, 9, 5),
        ];
        for (input, limit, initial, error, consumed, charged) in cases {
            let mut reader = Reader::new(&input, limit, initial);
            assert_eq!(reader.read_attachments(), Err(error));
            assert_eq!(input.len() - reader.remaining().len(), consumed);
            assert_eq!(reader.charged(), charged);
        }
    }
}
