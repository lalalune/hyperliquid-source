#![no_std]
//! Structural decoder for the selected Node115 ClientBlocks success payload.
//! Also projects the selected replay payload prefix over the same child readers.
extern crate alloc;

use alloc::{boxed::Box, vec::Vec};
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
    pub timestamp: AdmittedTimestamp,
    pub parent: Parent,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdmittedTimestamp {
    pub packed_date: u32,
    pub second_of_day: u32,
    pub nanoseconds: u32,
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

/// The fields read from the decoded Block at the selected replay comparison.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplayParentProjection {
    pub comparison_words: [u64; 2],
    pub successor: u64,
}

fn selected_replay_quorum(parent: &Parent) -> &QuorumCertificate {
    match parent {
        Parent::QuorumCertificate(certificate) => certificate,
        Parent::Timeout {
            certificate,
            quorum_certificate,
        } => quorum_certificate
            .as_ref()
            .unwrap_or(&certificate.quorum_certificate),
    }
}

/// The identity and predecessor bytes read from an incoming retained Block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetainedParentLink {
    pub identity: u64,
    pub predecessor: [u8; 32],
}

/// Read the retained-batch comparison operands from the typed incoming parent.
/// The expected predecessor's bytes are supplied by the previous Block owner
/// on the native path and are outside this incoming projection.
pub fn replay_retained_parent_link(parent: &Parent) -> RetainedParentLink {
    let quorum = selected_replay_quorum(parent);
    RetainedParentLink {
        identity: quorum.fields[2],
        predecessor: quorum.hash,
    }
}

/// Project the two comparison words and the separate saturating successor.
/// The positional certificate scalars retain the names used by the wire codec.
pub fn replay_parent_projection(parent: &Parent) -> ReplayParentProjection {
    let fields = &selected_replay_quorum(parent).fields;
    let successor_basis = match parent {
        Parent::QuorumCertificate(_) => fields[2],
        Parent::Timeout { certificate, .. } => certificate.field,
    };
    ReplayParentProjection {
        comparison_words: [fields[0], fields[1]],
        successor: successor_basis.saturating_add(1),
    }
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
    InvalidTimestamp { seconds: i64, nanoseconds: u32 },
    LengthDoesNotFitMemory,
    AllocationFailed,
}

/// Apply the selected #115 ClientBlock timestamp admission to decoded scalar
/// values. `node115-daycount-date` supplies the separately qualified CE-day
/// constructor; this returns only the observed packed date/time fields.
pub fn admit_timestamp(seconds: i64, nanoseconds: u32) -> Result<AdmittedTimestamp, Error> {
    let invalid = || Error::InvalidTimestamp {
        seconds,
        nanoseconds,
    };
    let ce_day = seconds.div_euclid(86_400) + 719_163;
    let ce_day = i32::try_from(ce_day).map_err(|_| invalid())?;
    let packed_date = node115_daycount_date::node115_date_from_ce_days(ce_day);
    if packed_date == 0 {
        return Err(invalid());
    }
    let second_of_day = seconds.rem_euclid(86_400) as u32;
    if nanoseconds > 1_999_999_999 || (nanoseconds >= 1_000_000_000 && second_of_day % 60 != 59) {
        return Err(invalid());
    }
    Ok(AdmittedTimestamp {
        packed_date,
        second_of_day,
        nanoseconds,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome<'a> {
    pub result: Result<Vec<Client>, Error>,
    pub remaining: &'a [u8],
}

struct Decoder<'a> {
    remaining: &'a [u8],
    limit: Option<u64>,
    charged: u64,
}

impl<'a> Decoder<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self {
            remaining: input,
            limit: None,
            charged: 0,
        }
    }

    fn charge(&mut self, amount: u64) -> Result<(), Error> {
        if let Some(limit) = self.limit {
            let next = self
                .charged
                .checked_add(amount)
                .ok_or(Error::U64(U64Error::Limit))?;
            self.charged = next;
            if next > limit {
                return Err(Error::U64(U64Error::Limit));
            }
        }
        Ok(())
    }

    fn reserve_rows(&mut self, count: u64, width: u64) -> Result<(), Error> {
        if self.limit.is_some() {
            let amount = count
                .checked_mul(width)
                .ok_or(Error::U64(U64Error::Limit))?;
            self.charge(amount)?;
        }
        Ok(())
    }

    fn refund_row(&mut self, width: u64) {
        if self.limit.is_some() {
            self.charged -= width;
        }
    }

    fn u64(&mut self) -> Result<u64, Error> {
        let mut reader = Reader::new(self.remaining, self.limit, self.charged);
        let result = reader.read_u64().map_err(Error::U64);
        self.remaining = reader.remaining();
        self.charged = reader.charged();
        result
    }

    fn u32(&mut self) -> Result<u32, Error> {
        let mode = u32::from(self.limit.is_some());
        read_u32(
            &mut self.remaining,
            mode,
            self.limit.unwrap_or(0),
            &mut self.charged,
        )
        .map_err(Error::U32)
    }

    fn signed_i64(&mut self) -> Result<i64, Error> {
        self.charge(8)?;
        let mut cursor = SignedCursor::new(self.remaining);
        let result = cursor.read_signed(0).map_err(Error::Signed);
        self.remaining = cursor.remaining();
        result
    }

    fn raw<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.charge(N as u64)?;
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
        self.charge(u64::try_from(length).map_err(|_| Error::U64(U64Error::Limit))?)?;
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
        let mut reader = Reader::new(self.remaining, self.limit, self.charged);
        let first = reader.read_four();
        self.remaining = reader.remaining();
        self.charged = reader.charged();
        let first = first.map_err(Error::U64)?;
        let mut reader = Reader::new(self.remaining, self.limit, self.charged);
        let second = reader.read_four();
        self.remaining = reader.remaining();
        self.charged = reader.charged();
        let second = second.map_err(Error::U64)?;
        let mut limbs = [0; 8];
        limbs[..4].copy_from_slice(&first);
        limbs[4..].copy_from_slice(&second);
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
        self.reserve_rows(count, 96)?;
        let mut votes = Vec::new();
        for _ in 0..count {
            self.refund_row(96);
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
        self.reserve_rows(count, 104)?;
        let mut votes = Vec::new();
        for _ in 0..count {
            self.refund_row(104);
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
        self.reserve_rows(count, 32)?;
        let mut hashes = Vec::new();
        for _ in 0..count {
            self.refund_row(32);
            hashes.try_reserve(1).map_err(|_| Error::AllocationFailed)?;
            hashes.push(self.raw::<32>()?);
        }
        let seconds = self.signed_i64()?;
        let nanoseconds = self.u32()?;
        let timestamp = admit_timestamp(seconds, nanoseconds)?;
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
            timestamp,
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

    fn block(&mut self) -> Result<Block, Error> {
        Ok(Block {
            signature: self.signature()?,
            header: self.header()?,
            commit_proof: if self.option_tag()? {
                Some(self.commit_proof()?)
            } else {
                None
            },
        })
    }

    fn blob(&mut self) -> Result<Vec<u8>, Error> {
        let length = usize::try_from(self.u64()?).map_err(|_| Error::LengthDoesNotFitMemory)?;
        self.bytes(length)
    }

    fn attachments(&mut self) -> Result<Vec<Attachment>, Error> {
        let count = self.u64()?;
        self.reserve_rows(count, 40)?;
        let mut attachments = Vec::new();
        for _ in 0..count {
            self.refund_row(40);
            attachments
                .try_reserve(1)
                .map_err(|_| Error::AllocationFailed)?;
            let hash = self.raw::<32>()?;
            attachments.push(Attachment {
                hash,
                bytes: self.blob()?,
            });
        }
        Ok(attachments)
    }

    fn client(&mut self) -> Result<Client, Error> {
        Ok(Client {
            block: self.block()?,
            attachments: self.attachments()?,
        })
    }

    fn replay(&mut self) -> Result<ReplayPayload, ReplayError> {
        match self.u32()? {
            0 => {
                let block = Box::new(self.block()?);
                let attachments = if self.option_tag()? {
                    Some(self.attachments()?)
                } else {
                    None
                };
                Ok(ReplayPayload::Block { block, attachments })
            }
            1 => Ok(ReplayPayload::Tx(self.blob()?)),
            tag => Err(ReplayError::InvalidTag(tag)),
        }
    }
}

/// Decode one success payload prefix, starting at `Vec(Client)` after its two
/// outer U32(0) tags. Trailing bytes are returned untouched. This API uses
/// unmetered structural reads; caller-specific charge policy is not inferred.
pub fn decode_payload_prefix(input: &[u8]) -> Outcome<'_> {
    let mut decoder = Decoder::new(input);
    let result = (|| {
        let count = decoder.u64()?;
        decoder.reserve_rows(count, 16)?;
        let mut clients = Vec::new();
        for _ in 0..count {
            decoder.refund_row(16);
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

/// Metered structural result with cursor and cumulative charge preserved on errors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MeteredOutcome<'a> {
    pub result: Result<Vec<Client>, Error>,
    pub remaining: &'a [u8],
    pub charged: u64,
}

/// Decode one selected success payload using the native reader's canonical
/// unlimited (`None`) or limited (`Some`) charge mode. Logical vote rows are
/// retained; this does not model native map normalization or allocation ABI.
pub fn decode_payload_prefix_metered(
    input: &[u8],
    limit: Option<u64>,
    charged: u64,
) -> MeteredOutcome<'_> {
    let mut decoder = Decoder {
        remaining: input,
        limit,
        charged,
    };
    let result = (|| {
        let count = decoder.u64()?;
        decoder.reserve_rows(count, 16)?;
        let mut clients = Vec::new();
        for _ in 0..count {
            decoder.refund_row(16);
            clients
                .try_reserve(1)
                .map_err(|_| Error::AllocationFailed)?;
            clients.push(decoder.client()?);
        }
        Ok(clients)
    })();
    MeteredOutcome {
        result,
        remaining: decoder.remaining,
        charged: decoder.charged,
    }
}

/// Replay-specific wire alternatives. An absent attachment list is distinct
/// from a present empty list. Tx bytes are retained as an opaque payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReplayPayload {
    Block {
        block: Box<Block>,
        attachments: Option<Vec<Attachment>>,
    },
    Tx(Vec<u8>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplayError {
    Decode(Error),
    InvalidTag(u32),
}

impl From<Error> for ReplayError {
    fn from(error: Error) -> Self {
        Self::Decode(error)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayOutcome<'a> {
    pub result: Result<ReplayPayload, ReplayError>,
    pub remaining: &'a [u8],
    pub charged: u64,
}

/// Decode the ClientBlockWireOrTx payload at the selected replay wrapper.
/// The supplied limit starts a fresh, cumulative reader. The native wrapper
/// accepts a prefix; the suffix is returned for offline accounting.
pub fn decode_replay_payload_prefix(input: &[u8], limit: u64) -> ReplayOutcome<'_> {
    let mut decoder = Decoder {
        remaining: input,
        limit: Some(limit),
        charged: 0,
    };
    ReplayOutcome {
        result: decoder.replay(),
        remaining: decoder.remaining,
        charged: decoder.charged,
    }
}
