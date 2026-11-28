//! Prefix encoding for the selected replay Block-or-Tx writer.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;
use alloc::vec::Vec;

use node115_varint_buffer_writer::{Error as VarintError, write_u64};

use node115_client_block_success::{
    AdmittedTimestamp, Attachment, Block, CommitProof, Header, Parent, QuorumCertificate,
    ReplayPayload, Signature, TimeoutCertificate, admit_timestamp,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplayEncodeError {
    Varint(VarintError),
    BufferGrowth,
    InvalidTimestamp,
}

struct Output(Vec<u8>);

impl Output {
    fn scalar(&mut self, value: u64) -> Result<(), ReplayEncodeError> {
        write_u64(&mut self.0, value).map_err(ReplayEncodeError::Varint)
    }

    fn raw(&mut self, bytes: &[u8]) -> Result<(), ReplayEncodeError> {
        self.0
            .try_reserve(bytes.len())
            .map_err(|_| ReplayEncodeError::BufferGrowth)?;
        self.0.extend_from_slice(bytes);
        Ok(())
    }

    fn length(&mut self, length: usize) -> Result<(), ReplayEncodeError> {
        self.scalar(length as u64)
    }

    fn blob(&mut self, bytes: &[u8]) -> Result<(), ReplayEncodeError> {
        self.length(bytes.len())?;
        self.raw(bytes)
    }

    fn option<T>(
        &mut self,
        value: Option<&T>,
        write: impl FnOnce(&mut Self, &T) -> Result<(), ReplayEncodeError>,
    ) -> Result<(), ReplayEncodeError> {
        self.raw(&[u8::from(value.is_some())])?;
        if let Some(value) = value {
            write(self, value)?;
        }
        Ok(())
    }

    fn signature(&mut self, value: &Signature) -> Result<(), ReplayEncodeError> {
        for limb in value.limbs {
            self.scalar(limb)?;
        }
        self.raw(&[value.recovery])
    }

    fn quorum(&mut self, value: &QuorumCertificate) -> Result<(), ReplayEncodeError> {
        for field in value.fields {
            self.scalar(field)?;
        }
        self.raw(&value.hash)?;
        self.length(value.votes.len())?;
        for vote in &value.votes {
            self.raw(&vote.signer)?;
            self.signature(&vote.signature)?;
        }
        Ok(())
    }

    fn timeout(&mut self, value: &TimeoutCertificate) -> Result<(), ReplayEncodeError> {
        self.scalar(value.field)?;
        self.quorum(&value.quorum_certificate)?;
        self.length(value.votes.len())?;
        for vote in &value.votes {
            self.raw(&vote.signer)?;
            self.scalar(vote.field)?;
            self.signature(&vote.signature)?;
        }
        Ok(())
    }

    fn header(&mut self, value: &Header) -> Result<(), ReplayEncodeError> {
        let timestamp = value.timestamp;
        let seconds = unix_seconds(timestamp)?;
        self.raw(&value.address)?;
        self.length(value.hashes.len())?;
        for hash in &value.hashes {
            self.raw(hash)?;
        }
        self.scalar(((seconds << 1) ^ (seconds >> 63)) as u64)?;
        self.scalar(u64::from(timestamp.nanoseconds))?;
        match &value.parent {
            Parent::QuorumCertificate(certificate) => {
                self.scalar(0)?;
                self.quorum(certificate)
            }
            Parent::Timeout {
                certificate,
                quorum_certificate,
            } => {
                self.scalar(1)?;
                self.timeout(certificate)?;
                self.option(quorum_certificate.as_ref(), Self::quorum)
            }
        }
    }

    fn proof(&mut self, value: &CommitProof) -> Result<(), ReplayEncodeError> {
        self.signature(&value.signature)?;
        self.header(&value.header)?;
        self.quorum(&value.quorum_certificate)
    }

    fn block(&mut self, value: &Block) -> Result<(), ReplayEncodeError> {
        self.signature(&value.signature)?;
        self.header(&value.header)?;
        self.option(value.commit_proof.as_ref(), Self::proof)
    }

    fn attachments(&mut self, rows: &[Attachment]) -> Result<(), ReplayEncodeError> {
        self.length(rows.len())?;
        for row in rows {
            self.raw(&row.hash)?;
            self.blob(&row.bytes)?;
        }
        Ok(())
    }
}

/// Inverse of the owning decoder's date constructor on successfully decoded
/// fields. Check the full packed word and the clock domain through that same
/// admission helper before emitting independent fixture bytes.
fn unix_seconds(value: AdmittedTimestamp) -> Result<i64, ReplayEncodeError> {
    let year = i64::from((value.packed_date as i32) >> 13);
    let ordinal = i64::from((value.packed_date >> 4) & 0x1ff);
    let previous_year = year - 1;
    let days = 365 * previous_year + previous_year.div_euclid(4) - previous_year.div_euclid(100)
        + previous_year.div_euclid(400)
        + ordinal
        - 719_163;
    let seconds = days * 86_400 + i64::from(value.second_of_day);
    if admit_timestamp(seconds, value.nanoseconds) != Ok(value) {
        return Err(ReplayEncodeError::InvalidTimestamp);
    }
    Ok(seconds)
}

/// Encode the same logical replay prefix returned by the selected decoder.
/// The output omits transport framing, compression and native owner layout.
pub fn encode_replay_payload(payload: &ReplayPayload) -> Result<Vec<u8>, ReplayEncodeError> {
    let mut output = Output(Vec::new());
    match payload {
        ReplayPayload::Block { block, attachments } => {
            output.scalar(0)?;
            output.block(block)?;
            output.option(attachments.as_ref(), |out, rows| out.attachments(rows))?;
        }
        ReplayPayload::Tx(bytes) => {
            output.scalar(1)?;
            output.blob(bytes)?;
        }
    }
    Ok(output.0)
}
