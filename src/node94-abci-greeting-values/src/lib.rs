//! Independently authored values and Reader state for node94's ABCI greeting.
//!
//! The contract is conditional on the frozen packet's ordinary-return/resource
//! premises. These types are safe logical representations, not native ABI types.
//! No framing, peer authentication, signature verification or network I/O occurs.

#![forbid(unsafe_code)]

use hl_bincode_varint::{DecodeError, PayloadOrder, ReaderError};
use std::collections::BTreeMap;

/// The active signature fields read from the wire; the final byte is unrestricted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Signature {
    pub limbs: [u64; 8],
    pub recovery: u8,
}

/// Last equal key wins. Array keys compare unsigned bytes lexicographically.
pub type SignatureMap = BTreeMap<[u8; 20], Signature>;

/// Wire-order scalar pair and fixed payload; native storage orders these differently.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Record {
    pub first: u64,
    pub second: u64,
    pub bytes: [u8; 2048],
}

/// The complete active greeting value. Variant names label the recovered tags.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Greeting {
    Data0 {
        bytes: Vec<u8>,
        scalar: u64,
        hash: [u8; 32],
        signatures: SignatureMap,
    },
    Data1 {
        bytes: Vec<u8>,
        scalar: u64,
        hash: [u8; 32],
        first: SignatureMap,
        second: SignatureMap,
    },
    Data2 {
        bytes: Vec<u8>,
        scalar: u64,
        records: Box<[Record; 3]>,
    },
    /// Three scalars in wire order, not the native b,c,a field placement.
    Triple([u64; 3]),
    Empty2,
    Empty3,
    Empty4,
    Empty5,
}

/// Only established active native error fields; no inactive union bytes or layout.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NativeError {
    UnexpectedEnd {
        needed: u64,
    },
    BulkUnexpectedEnd,
    LimitExceeded,
    InvalidIntegerType {
        expected: u8,
        found: u8,
    },
    UnexpectedVariant {
        type_name: &'static str,
        minimum: u32,
        maximum: u32,
        found: u32,
    },
}

/// Safe constructor policies, distinct from native decode errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StateError {
    SpanTooLarge,
    CursorOutOfBounds,
}

/// Allocation refusal is a safe host policy, not an invented native error kind.
/// Standard map/box allocation can still abort on exhaustion; no complete
/// fallible-allocation guarantee is made.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    Native(NativeError),
    InvalidState(StateError),
    HostAllocation,
}

impl From<NativeError> for Error {
    fn from(value: NativeError) -> Self {
        Self::Native(value)
    }
}

/// A safe supplied Reader. `None` corresponds to canonical native tag0 and
/// `Some(limit)` to tag1, including zero upper tag bits. Disabled charging
/// preserves the supplied charged word, even when it is u64::MAX.
#[derive(Clone, Debug)]
pub struct Reader<'a> {
    input: &'a [u8],
    cursor: usize,
    limit: Option<u64>,
    charged: u64,
}

impl<'a> Reader<'a> {
    pub fn new(
        input: &'a [u8],
        cursor: usize,
        limit: Option<u64>,
        charged: u64,
    ) -> Result<Self, StateError> {
        if input.len() as u128 > i64::MAX as u128 {
            return Err(StateError::SpanTooLarge);
        }
        if cursor > input.len() {
            return Err(StateError::CursorOutOfBounds);
        }
        Ok(Self {
            input,
            cursor,
            limit,
            charged,
        })
    }

    pub fn cursor(&self) -> usize {
        self.cursor
    }

    pub fn remaining(&self) -> usize {
        self.input.len() - self.cursor
    }

    pub fn charged(&self) -> u64 {
        self.charged
    }

    pub fn remaining_bytes(&self) -> &'a [u8] {
        &self.input[self.cursor..]
    }

    fn charge(&mut self, amount: u64) -> Result<(), Error> {
        if let Some(limit) = self.limit {
            let total = self
                .charged
                .checked_add(amount)
                .ok_or(NativeError::LimitExceeded)?;
            self.charged = total;
            if total > limit {
                return Err(NativeError::LimitExceeded.into());
            }
        }
        Ok(())
    }

    fn refund(&mut self, amount: u64) {
        if self.limit.is_some() {
            // Only accepted map/group reservations reach these private calls.
            self.charged = self
                .charged
                .checked_sub(amount)
                .expect("proved reservation invariant");
        }
    }

    fn reader_error(error: ReaderError, expected: u8) -> Error {
        match error {
            ReaderError::UnexpectedEnd { needed } => NativeError::UnexpectedEnd {
                needed: needed as u64,
            }
            .into(),
            ReaderError::InvalidIntegerType { found_code, .. } => NativeError::InvalidIntegerType {
                expected,
                found: found_code,
            }
            .into(),
        }
    }

    fn u32(&mut self) -> Result<u32, Error> {
        self.charge(4)?;
        let mut tail = self.remaining_bytes();
        if tail.len() > 4 && tail[0] >= 253 {
            let found = match tail[0] {
                253 => 3,
                254 => 4,
                _ => 12,
            };
            return Err(NativeError::InvalidIntegerType { expected: 2, found }.into());
        }
        // For supported fast markers the threshold guarantees the payload fits,
        // so the existing Reader has the same successful value/consumption.
        let result = hl_bincode_varint::read_u32(&mut tail, PayloadOrder::Little);
        self.cursor = self.input.len() - tail.len();
        result.map_err(|error| Self::reader_error(error, 2))
    }

    fn u64(&mut self, usize_kind: bool) -> Result<u64, Error> {
        self.charge(8)?;
        let mut tail = self.remaining_bytes();
        if tail.len() > 8 {
            return match hl_bincode_varint::decode_u64_slice_fast(tail) {
                Ok(decoded) => {
                    self.cursor += decoded.consumed;
                    Ok(decoded.value)
                }
                Err(DecodeError::RejectedMarker { marker }) => {
                    let expected = if usize_kind { 5 } else { 2 };
                    let found = if marker == 254 { 4 } else { 12 };
                    Err(NativeError::InvalidIntegerType { expected, found }.into())
                }
                Err(DecodeError::FastPathUnavailable { .. }) => {
                    unreachable!("pinned provider threshold")
                }
            };
        }
        let result = hl_bincode_varint::read_u64(&mut tail, PayloadOrder::Little);
        self.cursor = self.input.len() - tail.len();
        result.map_err(|error| Self::reader_error(error, if usize_kind { 5 } else { 3 }))
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.charge(N as u64)?;
        if self.remaining() < N {
            return Err(NativeError::UnexpectedEnd {
                needed: (N - self.remaining()) as u64,
            }
            .into());
        }
        let mut bytes = [0; N];
        bytes.copy_from_slice(&self.input[self.cursor..self.cursor + N]);
        self.cursor += N;
        Ok(bytes)
    }

    fn vector(&mut self) -> Result<Vec<u8>, Error> {
        let length = self.u64(false)?;
        self.charge(length)?;
        if length > self.remaining() as u64 {
            return Err(NativeError::BulkUnexpectedEnd.into());
        }
        // The comparison against this actual slice proves host representability.
        let length = usize::try_from(length).expect("bounded by remaining slice");
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|_| Error::HostAllocation)?;
        bytes.extend_from_slice(&self.input[self.cursor..self.cursor + length]);
        self.cursor += length;
        Ok(bytes)
    }

    fn group(&mut self) -> Result<[u64; 4], Error> {
        self.charge(32)?;
        let mut values = [0; 4];
        for value in &mut values {
            self.refund(8);
            *value = self.u64(false)?;
        }
        Ok(values)
    }

    fn signature(&mut self) -> Result<Signature, Error> {
        let mut limbs = [0; 8];
        limbs[..4].copy_from_slice(&self.group()?);
        limbs[4..].copy_from_slice(&self.group()?);
        let recovery = self.fixed::<1>()?[0];
        Ok(Signature { limbs, recovery })
    }

    fn map(&mut self) -> Result<SignatureMap, Error> {
        let count = self.u64(false)?;
        if self.limit.is_some() {
            let reserve = count.checked_mul(96).ok_or(NativeError::LimitExceeded)?;
            self.charge(reserve)?;
        }
        let mut map = SignatureMap::new();
        // No wire-count-sized allocation: finite input reaches a first failure
        // even when the disabled-limit count is u64::MAX.
        for _ in 0..count {
            self.refund(96);
            let key = self.fixed::<20>()?;
            let value = self.signature()?;
            map.insert(key, value);
        }
        Ok(map)
    }

    fn record(&mut self) -> Result<Record, Error> {
        let first = self.u64(true)?;
        let second = self.u64(true)?;
        let bytes = self.fixed::<2048>()?;
        Ok(Record {
            first,
            second,
            bytes,
        })
    }

    /// Decode exactly one greeting and retain the Reader state on every return.
    /// Trailing bytes are permitted. Errors never roll back previous consumption
    /// or finite stored charge. Host allocation failure is outside native matching.
    pub fn decode(&mut self) -> Result<Greeting, Error> {
        match self.u32()? {
            0 => {
                let bytes = self.vector()?;
                let scalar = self.u64(false)?;
                match self.u32()? {
                    0 => {
                        let hash = self.fixed::<32>()?;
                        let signatures = self.map()?;
                        Ok(Greeting::Data0 {
                            bytes,
                            scalar,
                            hash,
                            signatures,
                        })
                    }
                    1 => {
                        let hash = self.fixed::<32>()?;
                        let first = self.map()?;
                        let second = self.map()?;
                        Ok(Greeting::Data1 {
                            bytes,
                            scalar,
                            hash,
                            first,
                            second,
                        })
                    }
                    2 => {
                        let first = self.record()?;
                        let second = self.record()?;
                        let third = self.record()?;
                        let records = Box::new([first, second, third]);
                        Ok(Greeting::Data2 {
                            bytes,
                            scalar,
                            records,
                        })
                    }
                    found => Err(NativeError::UnexpectedVariant {
                        type_name: "GreetingHash",
                        minimum: 0,
                        maximum: 2,
                        found,
                    }
                    .into()),
                }
            }
            1 => {
                let first = self.u64(false)?;
                let second = self.u64(false)?;
                let third = self.u64(false)?;
                Ok(Greeting::Triple([first, second, third]))
            }
            2 => Ok(Greeting::Empty2),
            3 => Ok(Greeting::Empty3),
            4 => Ok(Greeting::Empty4),
            5 => Ok(Greeting::Empty5),
            found => Err(NativeError::UnexpectedVariant {
                type_name: "AbciStreamGreeting",
                minimum: 0,
                maximum: 5,
                found,
            }
            .into()),
        }
    }
}

/// A successful selected EDX=0 caller projection. Errors have no consumed word.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsumedGreeting {
    pub greeting: Greeting,
    pub consumed: usize,
}

/// Start the selected caller's enabled Reader at cursor0/charged0. This adapter
/// does not expose internal Reader state on error or require input exhaustion.
pub fn decode_with_limit(input: &[u8], limit: u64) -> Result<ConsumedGreeting, Error> {
    let mut reader = Reader::new(input, 0, Some(limit), 0).map_err(Error::InvalidState)?;
    let greeting = reader.decode()?;
    Ok(ConsumedGreeting {
        greeting,
        consumed: reader.cursor(),
    })
}
