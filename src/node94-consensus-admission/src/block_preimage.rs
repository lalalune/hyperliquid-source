//! Conditional node94 selector-0 value contract from `RE-008-block-preimage-94`.
//!
//! This offline encoder preserves supplied vector order and claimed identities.
//! It does not validate calendars, signatures, certificates or block admission.
//! Native equivalence assumes the packet's stable, valid, disjoint memory and
//! ordinary-success premises; digest equivalence additionally assumes the
//! credited native Keccak permutation identification.

use crate::{Qc, SignatureBytes, SignedBlock, Tc, TimeoutVote};
use hl_bincode_varint::{encode_u32, encode_u64, encoded_len_u32, encoded_len_u64, PayloadOrder};
use node94_action_signable::keccak256;
use std::fmt;

const PREFIX: &[u8; 29] = b"Hyperliquid Consensus Payload";
const MAX_LENGTH: usize = isize::MAX as usize;

/// The three raw words read by the captured block-time serializer.
///
/// `packed_date >> 13` is a signed year; bits 4..12 are an ordinal. Low four
/// bits are ignored. All raw words are admitted, including ordinal zero and
/// seconds/nanoseconds outside conventional calendar ranges.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackedBlockTime {
    pub packed_date: i32,
    pub seconds: u32,
    pub nanoseconds: u32,
}

impl PackedBlockTime {
    /// Calendar-derived signed seconds, without clamping or normalization checks.
    ///
    /// Across all raw inputs the result lies in
    /// `-8_334_632_937_600..=8_214_605_908_095` and fits in i64.
    #[must_use]
    pub const fn timestamp_seconds(self) -> i64 {
        let previous_year = (self.packed_date >> 13) as i64 - 1;
        let ordinal = ((self.packed_date as u32 >> 4) & 511) as i64;
        let day = 365 * previous_year + previous_year.div_euclid(4) - previous_year.div_euclid(100)
            + previous_year.div_euclid(400)
            + ordinal
            - 719_163;
        day * 86_400 + self.seconds as i64
    }
}

/// Safe API refusals; these are not captured native error discriminants.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockPreimageError {
    /// An encoded length, count or native source span exceeds the supported bound.
    LengthOverflow,
    /// Reserving the complete preimage buffer failed.
    AllocationFailure,
}

impl fmt::Display for BlockPreimageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::LengthOverflow => "block preimage length exceeds supported bounds",
            Self::AllocationFailure => "block preimage allocation failed",
        })
    }
}

impl std::error::Error for BlockPreimageError {}

fn add(total: &mut usize, amount: usize) -> Result<(), BlockPreimageError> {
    *total = total
        .checked_add(amount)
        .filter(|n| *n <= MAX_LENGTH)
        .ok_or(BlockPreimageError::LengthOverflow)?;
    Ok(())
}

fn count(length: usize, native_stride: usize) -> Result<u64, BlockPreimageError> {
    length
        .checked_mul(native_stride)
        .filter(|n| *n <= MAX_LENGTH)
        .ok_or(BlockPreimageError::LengthOverflow)?;
    u64::try_from(length).map_err(|_| BlockPreimageError::LengthOverflow)
}

fn zigzag(time: PackedBlockTime) -> u64 {
    let seconds = time.timestamp_seconds();
    if seconds < 0 {
        ((-seconds) as u64) * 2 - 1
    } else {
        (seconds as u64) * 2
    }
}

fn signature_words(signature: &SignatureBytes) -> impl Iterator<Item = u64> + '_ {
    signature.0[..64].chunks_exact(8).map(|limb| {
        let mut bytes = [0; 8];
        bytes.copy_from_slice(limb);
        u64::from_le_bytes(bytes)
    })
}

fn signature_len(signature: &SignatureBytes) -> usize {
    1 + signature_words(signature)
        .map(encoded_len_u64)
        .sum::<usize>()
}

fn qc_len(qc: &Qc) -> Result<usize, BlockPreimageError> {
    let n = count(qc.votes.len(), 96)?;
    let mut size = 32
        + encoded_len_u64(qc.hardfork.version)
        + encoded_len_u64(qc.hardfork.start_round.0)
        + encoded_len_u64(qc.round.0)
        + encoded_len_u64(n);
    for vote in &qc.votes {
        add(&mut size, 20 + signature_len(&vote.signature))?;
    }
    Ok(size)
}

fn timeout_len(timeout: &TimeoutVote) -> Result<usize, BlockPreimageError> {
    let mut size = signature_len(&timeout.signature) + 20 + encoded_len_u64(timeout.round.0);
    add(&mut size, qc_len(&timeout.qc)?)?;
    Ok(size)
}

fn tc_len(tc: Option<&Tc>) -> Result<usize, BlockPreimageError> {
    let mut size = 1;
    if let Some(tc) = tc {
        let n = count(tc.votes.len(), 184)?;
        add(&mut size, encoded_len_u64(tc.round.0) + encoded_len_u64(n))?;
        for timeout in &tc.votes {
            add(&mut size, timeout_len(timeout)?)?;
        }
    }
    Ok(size)
}

/// Exact full preimage length, including the 29-byte domain prefix and tag zero.
///
/// Also checks the separate native 32/96/184-byte source-span bounds. On a
/// narrower host the safe API additionally respects its isize allocation limit.
pub fn block_preimage_len(
    block: &SignedBlock,
    time: PackedBlockTime,
) -> Result<usize, BlockPreimageError> {
    let n = count(block.transaction_hashes.len(), 32)?;
    let mut size = PREFIX.len()
        + 1
        + 20
        + encoded_len_u64(block.round.0)
        + encoded_len_u64(n)
        + encoded_len_u64(zigzag(time))
        + encoded_len_u32(time.nanoseconds);
    add(&mut size, block.transaction_hashes.len() * 32)?;
    add(&mut size, qc_len(&block.qc)?)?;
    add(&mut size, tc_len(block.tc.as_ref())?)?;
    Ok(size)
}

fn word(out: &mut Vec<u8>, value: u64) {
    encode_u64(value, PayloadOrder::Little, out);
}

fn append_signature(out: &mut Vec<u8>, signature: &SignatureBytes) {
    for limb in signature_words(signature) {
        word(out, limb);
    }
    out.push(signature.0[64]);
}

fn append_qc(out: &mut Vec<u8>, qc: &Qc) {
    word(out, qc.hardfork.version);
    word(out, qc.hardfork.start_round.0);
    word(out, qc.round.0);
    out.extend_from_slice(&qc.block_hash.0);
    word(out, qc.votes.len() as u64);
    for vote in &qc.votes {
        out.extend_from_slice(&vote.signer.0);
        append_signature(out, &vote.signature);
    }
}

fn append_timeout(out: &mut Vec<u8>, timeout: &TimeoutVote) {
    append_signature(out, &timeout.signature);
    out.extend_from_slice(&timeout.signer.0);
    word(out, timeout.round.0);
    append_qc(out, &timeout.qc);
}

fn append_tc(out: &mut Vec<u8>, tc: Option<&Tc>) {
    out.push(u8::from(tc.is_some()));
    if let Some(tc) = tc {
        word(out, tc.round.0);
        word(out, tc.votes.len() as u64);
        for timeout in &tc.votes {
            append_timeout(out, timeout);
        }
    }
}

/// Builds the selector-0 preimage from existing values plus explicit packed time.
///
/// All vectors retain their supplied order. Outer block signature bytes and
/// signature padding are ignored; nested QC/timeout active signature bytes are
/// included. No signing, key access, recovery or state mutation occurs.
pub fn block_preimage(
    block: &SignedBlock,
    time: PackedBlockTime,
) -> Result<Vec<u8>, BlockPreimageError> {
    let size = block_preimage_len(block, time)?;
    let mut out = Vec::new();
    out.try_reserve_exact(size)
        .map_err(|_| BlockPreimageError::AllocationFailure)?;
    out.extend_from_slice(PREFIX);
    out.push(0);
    out.extend_from_slice(&block.proposer.0);
    word(&mut out, block.round.0);
    word(&mut out, block.transaction_hashes.len() as u64);
    for hash in &block.transaction_hashes {
        out.extend_from_slice(&hash.0);
    }
    word(&mut out, zigzag(time));
    encode_u32(time.nanoseconds, PayloadOrder::Little, &mut out);
    append_qc(&mut out, &block.qc);
    append_tc(&mut out, block.tc.as_ref());
    Ok(out)
}

/// Computes offline Keccak-256 of the reconstructed block preimage.
///
/// Correspondence with the captured digest is conditional on the packet's
/// native Keccak identity and memory/callee premises. This does not authenticate
/// the block or implement [`crate::AdmissionAuthenticator`].
pub fn block_digest(
    block: &SignedBlock,
    time: PackedBlockTime,
) -> Result<[u8; 32], BlockPreimageError> {
    let preimage = block_preimage(block, time)?;
    Ok(*keccak256(&preimage).as_bytes())
}
