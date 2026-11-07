#![no_std]
//! Structural decoder for the selected Node115 ClientBlocks success payload.
//! The outer response and nested Result tags have already been consumed.
extern crate alloc;

use alloc::vec::Vec;
use node115_signed_scalar::{Cursor as SignedCursor, DecodeError as SignedError};
use node115_u32_varint::{ReadError as U32Error, read_u32};
use node115_u64_reader_state::{Error as U64Error, Reader};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Signature {
    pub limbs: [u64; 8],
    pub recovery: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub address: [u8; 20],
    pub hashes: Vec<[u8; 32]>,
    /// Wire values only; calendar admission and packed native representation
    /// are outside this structural decoder.
    pub timestamp_seconds: i64,
    pub timestamp_nanos: u32,
    pub parent: Parent,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Parent {
    QuorumCertificate(QuorumCertificate),
    Timeout {
        certificate: TimeoutCertificate,
        quorum_certificate: Option<QuorumCertificate>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuorumCertificate {
    pub fields: [u64; 5],
    pub hash: [u8; 32],
    pub votes: Vec<QuorumVote>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TimeoutCertificate {
    pub field: u64,
    pub quorum_certificate: QuorumCertificate,
    pub votes: Vec<TimeoutVote>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuorumVote {
    pub signer: [u8; 20],
    pub signature: Signature,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimeoutVote {
    pub signer: [u8; 20],
    pub field: u64,
    pub signature: Signature,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitProof {
    pub signature: Signature,
    pub header: Header,
    pub quorum_certificate: QuorumCertificate,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    pub signature: Signature,
    pub header: Header,
    pub commit_proof: Option<CommitProof>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attachment {
    pub hash: [u8; 32],
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Client {
    pub block: Block,
    pub attachments: Vec<Attachment>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    U64(U64Error),
    U32(U32Error),
    Signed(SignedError),
    UnexpectedEnd { additional: usize },
    InvalidParentTag(u32),
    InvalidOption(u8),
    LengthDoesNotFitMemory,
    AllocationFailed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome<'a> {
    pub result: Result<Vec<Client>, Error>,
    pub remaining: &'a [u8],
}

struct Decoder<'a> {
    remaining: &'a [u8],
}

impl<'a> Decoder<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { remaining: input }
    }

    fn u64(&mut self) -> Result<u64, Error> {
        let mut reader = Reader::new(self.remaining, None, 0);
        let result = reader.read_u64().map_err(Error::U64);
        self.remaining = reader.remaining();
        result
    }

    fn u32(&mut self) -> Result<u32, Error> {
        let mut charged = 0;
        read_u32(&mut self.remaining, 0, 0, &mut charged).map_err(Error::U32)
    }

    fn signed_i64(&mut self) -> Result<i64, Error> {
        let mut cursor = SignedCursor::new(self.remaining);
        let result = cursor.read_signed(0).map_err(Error::Signed);
        self.remaining = cursor.remaining();
        result
    }

    fn raw<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        if self.remaining.len() < N {
            return Err(Error::UnexpectedEnd {
                additional: N - self.remaining.len(),
            });
        }
        let (head, tail) = self.remaining.split_at(N);
        let mut value = [0; N];
        value.copy_from_slice(head);
        self.remaining = tail;
        Ok(value)
    }

    fn bytes(&mut self, length: usize) -> Result<Vec<u8>, Error> {
        if self.remaining.len() < length {
            return Err(Error::UnexpectedEnd {
                additional: length - self.remaining.len(),
            });
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|_| Error::AllocationFailed)?;
        bytes.extend_from_slice(&self.remaining[..length]);
        self.remaining = &self.remaining[length..];
        Ok(bytes)
    }

    fn option_tag(&mut self) -> Result<bool, Error> {
        match self.raw::<1>()?[0] {
            0 => Ok(false),
            1 => Ok(true),
            tag => Err(Error::InvalidOption(tag)),
        }
    }

    fn signature(&mut self) -> Result<Signature, Error> {
        let mut limbs = [0; 8];
        for limb in &mut limbs {
            *limb = self.u64()?;
        }
        Ok(Signature {
            limbs,
            recovery: self.raw::<1>()?[0],
        })
    }

    fn quorum_vote(&mut self) -> Result<QuorumVote, Error> {
        Ok(QuorumVote {
            signer: self.raw::<20>()?,
            signature: self.signature()?,
        })
    }

    fn timeout_vote(&mut self) -> Result<TimeoutVote, Error> {
        Ok(TimeoutVote {
            signer: self.raw::<20>()?,
            field: self.u64()?,
            signature: self.signature()?,
        })
    }

    fn quorum_certificate(&mut self) -> Result<QuorumCertificate, Error> {
        let mut fields = [0; 5];
        for field in &mut fields {
            *field = self.u64()?;
        }
        let hash = self.raw::<32>()?;
        let count = self.u64()?;
        let mut votes = Vec::new();
        for _ in 0..count {
            votes.try_reserve(1).map_err(|_| Error::AllocationFailed)?;
            votes.push(self.quorum_vote()?);
        }
        Ok(QuorumCertificate {
            fields,
            hash,
            votes,
        })
    }

    fn timeout_certificate(&mut self) -> Result<TimeoutCertificate, Error> {
        let field = self.u64()?;
        let quorum_certificate = self.quorum_certificate()?;
        let count = self.u64()?;
        let mut votes = Vec::new();
        for _ in 0..count {
            votes.try_reserve(1).map_err(|_| Error::AllocationFailed)?;
            votes.push(self.timeout_vote()?);
        }
        Ok(TimeoutCertificate {
            field,
            quorum_certificate,
            votes,
        })
    }

    fn header(&mut self) -> Result<Header, Error> {
        let address = self.raw::<20>()?;
        let count = self.u64()?;
        let mut hashes = Vec::new();
        for _ in 0..count {
            hashes.try_reserve(1).map_err(|_| Error::AllocationFailed)?;
            hashes.push(self.raw::<32>()?);
        }
        let timestamp_seconds = self.signed_i64()?;
        let timestamp_nanos = self.u32()?;
        let parent = match self.u32()? {
            0 => Parent::QuorumCertificate(self.quorum_certificate()?),
            1 => {
                let certificate = self.timeout_certificate()?;
                let quorum_certificate = if self.option_tag()? {
                    Some(self.quorum_certificate()?)
                } else {
                    None
                };
                Parent::Timeout {
                    certificate,
                    quorum_certificate,
                }
            }
            tag => return Err(Error::InvalidParentTag(tag)),
        };
        Ok(Header {
            address,
            hashes,
            timestamp_seconds,
            timestamp_nanos,
            parent,
        })
    }

    fn commit_proof(&mut self) -> Result<CommitProof, Error> {
        Ok(CommitProof {
            signature: self.signature()?,
            header: self.header()?,
            quorum_certificate: self.quorum_certificate()?,
        })
    }

    fn client(&mut self) -> Result<Client, Error> {
        let block = Block {
            signature: self.signature()?,
            header: self.header()?,
            commit_proof: if self.option_tag()? {
                Some(self.commit_proof()?)
            } else {
                None
            },
        };
        let count = self.u64()?;
        let mut attachments = Vec::new();
        for _ in 0..count {
            attachments
                .try_reserve(1)
                .map_err(|_| Error::AllocationFailed)?;
            let hash = self.raw::<32>()?;
            let length = usize::try_from(self.u64()?).map_err(|_| Error::LengthDoesNotFitMemory)?;
            attachments.push(Attachment {
                hash,
                bytes: self.bytes(length)?,
            });
        }
        Ok(Client { block, attachments })
    }
}

/// Decode one success payload prefix, starting at `Vec(Client)` after its two
/// outer U32(0) tags. Trailing bytes are returned untouched. This API uses
/// unmetered structural reads; caller-specific charge policy is not inferred.
pub fn decode_payload_prefix(input: &[u8]) -> Outcome<'_> {
    let mut decoder = Decoder::new(input);
    let result = (|| {
        let count = decoder.u64()?;
        let mut clients = Vec::new();
        for _ in 0..count {
            clients
                .try_reserve(1)
                .map_err(|_| Error::AllocationFailed)?;
            clients.push(decoder.client()?);
        }
        Ok(clients)
    })();
    Outcome {
        result,
        remaining: decoder.remaining,
    }
}
