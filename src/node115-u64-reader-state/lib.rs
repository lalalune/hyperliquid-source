#![no_std]
//! Safe logical projection of the frozen Node115 reader relation.
//! This is not the original Rust ABI, enum layout or a complete codec.

/// Only active error fields observed in the selected native reader paths.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Native tag0; no input or an incomplete marked payload.
    UnexpectedEnd { additional: u64 },
    /// Native tag2; count overflow or the stored charge exceeds the limit.
    Limit,
    /// Native tag3; raw helper arguments, without inferred enum names.
    Invalid { expected_raw: u8, found_raw: u8 },
}

/// Exclusive safe state. `None` represents canonical unlimited mode0;
/// `Some(limit)` represents canonical limited mode1. Other raw modes excluded.
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

    fn charge(&mut self, amount: u64) -> Result<(), Error> {
        if let Some(limit) = self.limit {
            let next = self.charged.checked_add(amount).ok_or(Error::Limit)?;
            // The native store precedes its limit comparison. Do not roll back.
            self.charged = next;
            if next > limit {
                return Err(Error::Limit);
            }
        }
        Ok(())
    }

    /// Read one u64-shaped value, retaining observed partial state on errors.
    pub fn read_u64(&mut self) -> Result<u64, Error> {
        self.charge(8)?;
        let input = self.remaining;
        let slow = input.len() <= 8;
        let Some(&marker) = input.first() else {
            return Err(Error::UnexpectedEnd { additional: 1 });
        };
        // Native slow helper commits marker consumption before classification.
        if slow {
            self.remaining = &input[1..];
        }
        if marker < 251 {
            self.remaining = &input[1..];
            return Ok(u64::from(marker));
        }
        let width = match marker {
            251 => 3,
            252 => 5,
            253 => 9,
            _ => {
                return Err(Error::Invalid {
                    expected_raw: if slow { 3 } else { 2 },
                    found_raw: if marker == 254 { 4 } else { 12 },
                });
            }
        };
        if input.len() < width {
            return Err(Error::UnexpectedEnd {
                additional: (width - input.len()) as u64,
            });
        }
        // Nonminimal encodings are accepted; the native routes have no floor test.
        let mut value = [0; 8];
        value[..width - 1].copy_from_slice(&input[1..width]);
        self.remaining = &input[width..];
        Ok(u64::from_le_bytes(value))
    }

    /// Project the two selected callers' four-read aggregate, not an original type.
    pub fn read_four(&mut self) -> Result<[u64; 4], Error> {
        self.charge(32)?;
        let mut values = [0; 4];
        for value in &mut values {
            if self.limit.is_some() {
                // Successful precharge proves count>=32. Each read restores it.
                self.charged -= 8;
            }
            *value = self.read_u64()?;
        }
        Ok(values)
    }
}
