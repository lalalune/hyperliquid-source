//! Mode-1 wire/value projection of the node94 greeting reply decoder.
//!
//! Field names describe wire position, not recovered nominal types. Public
//! values are independent Rust types; native enum layout, B-tree nodes, heap
//! identity, error text and peer-acceptance policy are not reproduced.

use core::fmt;
use std::collections::BTreeMap;

use varint::{PayloadOrder, ReaderError};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MapValue {
    pub first: [u64; 4],
    pub second: [u64; 4],
    pub last: u8,
}

pub type Map = BTreeMap<[u8; 20], MapValue>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FixedRecord {
    pub first: u64,
    pub second: u64,
    pub bytes: [u8; 2048],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HashReply {
    Variant0 {
        bytes: [u8; 32],
        map: Map,
    },
    Variant1 {
        bytes: [u8; 32],
        first: Map,
        second: Map,
    },
    Variant2(Box<[FixedRecord; 3]>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Reply {
    Variant0 {
        bytes: Vec<u8>,
        word: u64,
        hash: HashReply,
    },
    /// Values in wire order. The target's three stored words are second, third, first.
    Variant1([u64; 3]),
    Variant2,
    Variant3,
    Variant4,
    Variant5,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Decoded {
    pub reply: Reply,
    pub consumed: usize,
    pub remaining: usize,
    /// Logical charge, which differs from wire length and allocation size.
    pub charged: u64,
}

/// Logical error projection; these discriminants are not the target ABI.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ErrorKind {
    UnexpectedEnd {
        needed: u64,
    },
    CollectionTooLong,
    Limit,
    InvalidIntegerType {
        expected: u8,
        found: u8,
    },
    UnexpectedVariant {
        type_name: &'static str,
        found: u32,
        max: u32,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Failure {
    pub kind: ErrorKind,
    /// Actual cursor progress, retained even though the target diagnostic reports zero.
    pub consumed: usize,
    pub charged: u64,
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "greeting decode at byte {}: {:?}",
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

    fn reader_error(&self, error: ReaderError, expected_override: Option<u8>) -> Failure {
        self.failure(match error {
            ReaderError::UnexpectedEnd { needed } => ErrorKind::UnexpectedEnd {
                needed: needed as u64,
            },
            ReaderError::InvalidIntegerType {
                expected_code,
                found_code,
            } => ErrorKind::InvalidIntegerType {
                expected: expected_override.unwrap_or(expected_code),
                found: found_code,
            },
        })
    }

    fn word(&mut self, kind5: bool) -> Result<u64, Failure> {
        if self.rest.len() > 8 {
            let tag = self.rest[0];
            if tag >= 0xfe {
                return Err(self.failure(ErrorKind::InvalidIntegerType {
                    expected: if kind5 { 5 } else { 2 },
                    found: if tag == 0xfe { 4 } else { 12 },
                }));
            }
            let decoded = varint::decode_u64_slice_fast(self.rest)
                .expect("more than eight bytes and an admitted u64 marker");
            self.rest = &self.rest[decoded.consumed..];
            Ok(decoded.value)
        } else {
            varint::read_u64(&mut self.rest, PayloadOrder::Little)
                .map_err(|error| self.reader_error(error, if kind5 { Some(5) } else { None }))
        }
    }

    fn charged_word(&mut self, kind5: bool) -> Result<u64, Failure> {
        self.charge(8)?;
        self.word(kind5)
    }

    fn tag(&mut self, type_name: &'static str, max: u32) -> Result<u32, Failure> {
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
            .map_err(|error| self.reader_error(error, None))?;
        if tag > max {
            return Err(self.failure(ErrorKind::UnexpectedVariant {
                type_name,
                found: tag,
                max,
            }));
        }
        Ok(tag)
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], Failure> {
        self.charge(N as u64)?;
        if self.rest.len() < N {
            return Err(self.failure(ErrorKind::UnexpectedEnd {
                needed: (N - self.rest.len()) as u64,
            }));
        }
        let mut bytes = [0; N];
        bytes.copy_from_slice(&self.rest[..N]);
        self.rest = &self.rest[N..];
        Ok(bytes)
    }

    fn bytes(&mut self) -> Result<Vec<u8>, Failure> {
        let count = self.charged_word(false)?;
        self.charge(count)?;
        if count > self.rest.len() as u64 {
            return Err(self.failure(ErrorKind::CollectionTooLong));
        }
        let count = count as usize;
        let bytes = self.rest[..count].to_vec();
        self.rest = &self.rest[count..];
        Ok(bytes)
    }

    fn words(&mut self) -> Result<[u64; 4], Failure> {
        self.charge(32)?;
        Ok([
            self.word(false)?,
            self.word(false)?,
            self.word(false)?,
            self.word(false)?,
        ])
    }

    fn map(&mut self) -> Result<Map, Failure> {
        let count = self.charged_word(false)?;
        let reserve = count
            .checked_mul(96)
            .ok_or_else(|| self.failure(ErrorKind::Limit))?;
        self.charge(reserve)?;
        let mut map = Map::new();
        for _ in 0..count {
            // The admitted reservation proves enough charge remains for each refund.
            self.charged -= 96;
            let key = self.fixed::<20>()?;
            let first = self.words()?;
            let second = self.words()?;
            let last = self.fixed::<1>()?[0];
            map.insert(
                key,
                MapValue {
                    first,
                    second,
                    last,
                },
            );
        }
        Ok(map)
    }

    fn record(&mut self) -> Result<FixedRecord, Failure> {
        let first = self.charged_word(true)?;
        let second = self.charged_word(true)?;
        let bytes = self.fixed::<2048>()?;
        Ok(FixedRecord {
            first,
            second,
            bytes,
        })
    }

    fn hash(&mut self) -> Result<HashReply, Failure> {
        match self.tag("GreetingHash", 2)? {
            0 => Ok(HashReply::Variant0 {
                bytes: self.fixed()?,
                map: self.map()?,
            }),
            1 => Ok(HashReply::Variant1 {
                bytes: self.fixed()?,
                first: self.map()?,
                second: self.map()?,
            }),
            2 => Ok(HashReply::Variant2(Box::new([
                self.record()?,
                self.record()?,
                self.record()?,
            ]))),
            _ => unreachable!("validated hash selector"),
        }
    }

    fn reply(&mut self) -> Result<Reply, Failure> {
        match self.tag("AbciStreamGreeting", 5)? {
            0 => Ok(Reply::Variant0 {
                bytes: self.bytes()?,
                word: self.charged_word(false)?,
                hash: self.hash()?,
            }),
            1 => Ok(Reply::Variant1([
                self.charged_word(false)?,
                self.charged_word(false)?,
                self.charged_word(false)?,
            ])),
            2 => Ok(Reply::Variant2),
            3 => Ok(Reply::Variant3),
            4 => Ok(Reply::Variant4),
            5 => Ok(Reply::Variant5),
            _ => unreachable!("validated greeting selector"),
        }
    }
}

/// Decode every reply variant with mode-1 logical charging, initially zero.
///
/// Nonminimal integers and a suffix are accepted. Errors preserve reached
/// cursor/charge state; the target wrapper's diagnostic consumed value is zero
/// for errors, independently of this actual cursor. Allocation failure follows
/// Rust's allocation behavior, not a recovered node error or allocator ABI.
pub fn decode(input: &[u8], limit: u64) -> Result<Decoded, Failure> {
    let mut reader = Reader {
        rest: input,
        original_len: input.len(),
        limit,
        charged: 0,
    };
    let reply = reader.reply()?;
    Ok(Decoded {
        reply,
        consumed: input.len() - reader.rest.len(),
        remaining: reader.rest.len(),
        charged: reader.charged,
    })
}
