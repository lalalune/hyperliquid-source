#![no_std]
//! Logical projection of node115's private four-word prefix operation.
//! Names and safe types are owned here, not claims about the original ABI.

use node115_u64_reader_state::{Error as ReadError, Reader};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fields {
    pub words: [u64; 4],
    pub tail: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Read(ReadError),
    Mode { found_raw: u8 },
}

/// Canonical mode0/1 and little-endian input only. Partial input consumption
/// and charge stores survive failure; this operation does not require EOF.
pub struct Decoder<'a> {
    remaining: &'a [u8],
    limit: Option<u64>,
    charged: u64,
}

impl<'a> Decoder<'a> {
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

    fn word(&mut self) -> Result<u64, Error> {
        let mut reader = Reader::new(self.remaining, self.limit, self.charged);
        let result = reader.read_u64();
        self.remaining = reader.remaining();
        self.charged = reader.charged();
        result.map_err(Error::Read)
    }

    fn mode(&mut self) -> Result<u8, Error> {
        if let Some(limit) = self.limit {
            let next = self
                .charged
                .checked_add(1)
                .ok_or(Error::Read(ReadError::Limit))?;
            self.charged = next;
            if next > limit {
                return Err(Error::Read(ReadError::Limit));
            }
        }
        let Some((&mode, rest)) = self.remaining.split_first() else {
            return Err(Error::Read(ReadError::UnexpectedEnd { additional: 1 }));
        };
        self.remaining = rest;
        Ok(mode)
    }

    pub fn decode(&mut self) -> Result<Fields, Error> {
        // Four distinct charge8 calls, not the other native aggregate's
        // upfront charge32. Each failed call retains its own partial state.
        let mut words = [0; 4];
        for word in &mut words {
            *word = self.word()?;
        }
        let tail = match self.mode()? {
            0 => None,
            1 => Some(self.word()?),
            found_raw => return Err(Error::Mode { found_raw }),
        };
        Ok(Fields { words, tail })
    }
}
