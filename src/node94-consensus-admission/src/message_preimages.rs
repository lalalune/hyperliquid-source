//! Offline value encoders for node #94 consensus selectors 2, 3 and 4.
//!
//! The native correspondence is conditional on the stable, disjoint inputs and
//! finite truthful tree metadata stated in `RE-008-consensus-other-preimages-94`.
//! Collection slices represent native in-order traversal; no sorting or
//! deduplication occurs here. These APIs do not authenticate messages, validate
//! signatures, recover public keys or change [`crate::AdmissionAuthenticator`].
//!
//! Digest helpers reuse the existing MIT `node94-action-signable` Keccak code.
//! The packet establishes multiblock framing; native permutation identity is
//! conditional on the credited RE-005 structural evidence, not a new complete
//! proof of the permutation.

#![forbid(unsafe_code)]

use crate::{BlockHash, Qc, Round, SignatureBytes, ValidatorAddress};
use hl_bincode_varint::{encode_u32, encode_u64, encoded_len_u32, encoded_len_u64, PayloadOrder};
use std::fmt;

const PREFIX: &[u8; 29] = b"Hyperliquid Consensus Payload";

/// Checked sizing or allocation failed before any preimage is returned.
/// These are safe API errors, not claims about native panic payloads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreimageError {
    LengthOverflow,
    AllocationFailed,
}

impl fmt::Display for PreimageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::LengthOverflow => "consensus preimage length exceeds the supported bound",
            Self::AllocationFailed => "consensus preimage allocation failed",
        })
    }
}

impl std::error::Error for PreimageError {}

/// A key/word pair in the caller-supplied native traversal order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OrderedWordEntry {
    pub address: ValidatorAddress,
    pub word: u64,
}

/// Two native words followed by a 32-byte hash in the encoded summary.
/// The names avoid assigning unsupported protocol meanings to the words.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConsensusSummary {
    pub first: u64,
    pub second: u64,
    pub block_hash: BlockHash,
}

/// Selected heartbeat snapshot fields; `None` differs from `Some(&[])`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeartbeatSnapshot<'a> {
    pub stakes: Option<&'a [OrderedWordEntry]>,
    pub jailed: Option<&'a [ValidatorAddress]>,
    pub evm_word: u64,
    pub summaries: Option<&'a [ConsensusSummary; 3]>,
}

/// Active heartbeat signing fields, excluding the outer signature.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeartbeatMessage<'a> {
    pub signer: ValidatorAddress,
    pub round: Round,
    pub random: u32,
    pub snapshot: Option<HeartbeatSnapshot<'a>>,
    pub peers: Option<&'a [OrderedWordEntry]>,
}

fn add(total: &mut usize, extra: usize) -> Result<(), PreimageError> {
    *total = total
        .checked_add(extra)
        .filter(|n| *n <= isize::MAX as usize && (*n as u128) < (1u128 << 63))
        .ok_or(PreimageError::LengthOverflow)?;
    Ok(())
}

fn count(value: usize) -> Result<u64, PreimageError> {
    u64::try_from(value).map_err(|_| PreimageError::LengthOverflow)
}

fn word(out: &mut Vec<u8>, value: u64) {
    encode_u64(value, PayloadOrder::Little, out);
}

fn begin(tag: u8, len: usize) -> Result<Vec<u8>, PreimageError> {
    let mut out = Vec::new();
    out.try_reserve_exact(len)
        .map_err(|_| PreimageError::AllocationFailed)?;
    out.extend_from_slice(PREFIX);
    out.push(tag);
    Ok(out)
}

fn signature_words(signature: &SignatureBytes) -> impl Iterator<Item = u64> + '_ {
    signature.0[..64].chunks_exact(8).map(|bytes| {
        let mut limb = [0; 8];
        limb.copy_from_slice(bytes);
        u64::from_le_bytes(limb)
    })
}

/// Exact length of the variant-2 preimage, including its 29-byte prefix.
pub fn timeout_preimage_len(qc: &Qc, round: Round) -> Result<usize, PreimageError> {
    let mut size = 82; // prefix + tag + outer signer + QC hash
    for value in [
        round.0,
        qc.hardfork.version,
        qc.hardfork.start_round.0,
        qc.round.0,
    ] {
        add(&mut size, encoded_len_u64(value))?;
    }
    add(&mut size, encoded_len_u64(count(qc.votes.len())?))?;
    for vote in &qc.votes {
        add(&mut size, 21)?; // signer + unrestricted final signature byte
        for limb in signature_words(&vote.signature) {
            add(&mut size, encoded_len_u64(limb))?;
        }
    }
    Ok(size)
}

/// Encode a timeout's explicit claimed signer, round, QC fields and ordered votes.
///
/// Each nested 72-byte signature contributes eight little-endian u64 limbs
/// encoded as varints, then byte 64. Bytes 65..71 are inactive padding here.
/// This projection asserts neither ECDSA canonicality nor a valid recovery ID.
/// The outer timeout signature is not an input. Existing authentication traits
/// remain separate; this helper does not infer the claimed signer from a QC.
pub fn timeout_preimage(
    qc: &Qc,
    round: Round,
    signer: ValidatorAddress,
) -> Result<Vec<u8>, PreimageError> {
    let len = timeout_preimage_len(qc, round)?;
    let mut out = begin(2, len)?;
    out.extend_from_slice(&signer.0);
    for value in [
        round.0,
        qc.hardfork.version,
        qc.hardfork.start_round.0,
        qc.round.0,
    ] {
        word(&mut out, value);
    }
    out.extend_from_slice(&qc.block_hash.0);
    word(&mut out, count(qc.votes.len())?);
    for vote in &qc.votes {
        out.extend_from_slice(&vote.signer.0);
        for limb in signature_words(&vote.signature) {
            word(&mut out, limb);
        }
        out.push(vote.signature.0[64]);
    }
    debug_assert_eq!(out.len(), len);
    Ok(out)
}

fn map_len(rows: Option<&[OrderedWordEntry]>) -> Result<usize, PreimageError> {
    let mut size = 1;
    if let Some(rows) = rows {
        add(&mut size, encoded_len_u64(count(rows.len())?))?;
        for row in rows {
            add(&mut size, 20 + encoded_len_u64(row.word))?;
        }
    }
    Ok(size)
}

fn map(out: &mut Vec<u8>, rows: Option<&[OrderedWordEntry]>) -> Result<(), PreimageError> {
    out.push(u8::from(rows.is_some()));
    if let Some(rows) = rows {
        word(out, count(rows.len())?);
        for row in rows {
            out.extend_from_slice(&row.address.0);
            word(out, row.word);
        }
    }
    Ok(())
}

/// Exact length of the variant-3 preimage, with distinct nested option markers.
pub fn heartbeat_preimage_len(message: &HeartbeatMessage<'_>) -> Result<usize, PreimageError> {
    let mut size = 51; // prefix + tag + signer + snapshot presence
    add(&mut size, encoded_len_u64(message.round.0))?;
    add(&mut size, encoded_len_u32(message.random))?;
    add(&mut size, map_len(message.peers)?)?;
    if let Some(snapshot) = message.snapshot {
        add(&mut size, map_len(snapshot.stakes)?)?;
        add(&mut size, 1)?; // jailed presence
        if let Some(rows) = snapshot.jailed {
            add(&mut size, encoded_len_u64(count(rows.len())?))?;
            add(
                &mut size,
                rows.len()
                    .checked_mul(20)
                    .ok_or(PreimageError::LengthOverflow)?,
            )?;
        }
        add(&mut size, encoded_len_u64(snapshot.evm_word))?;
        add(&mut size, 1)?; // summary triple presence
        if let Some(summaries) = snapshot.summaries {
            for summary in summaries {
                add(
                    &mut size,
                    32 + encoded_len_u64(summary.first) + encoded_len_u64(summary.second),
                )?;
            }
        }
    }
    Ok(size)
}

/// Encode a heartbeat, preserving supplied collection order and option presence.
/// Native equivalence requires each slice to be the finite tree's in-order
/// sequence with truthful count/parent/height metadata; no tree is constructed.
pub fn heartbeat_preimage(message: &HeartbeatMessage<'_>) -> Result<Vec<u8>, PreimageError> {
    let len = heartbeat_preimage_len(message)?;
    let mut out = begin(3, len)?;
    out.extend_from_slice(&message.signer.0);
    word(&mut out, message.round.0);
    out.push(u8::from(message.snapshot.is_some()));
    if let Some(snapshot) = message.snapshot {
        map(&mut out, snapshot.stakes)?;
        out.push(u8::from(snapshot.jailed.is_some()));
        if let Some(rows) = snapshot.jailed {
            word(&mut out, count(rows.len())?);
            for row in rows {
                out.extend_from_slice(&row.0);
            }
        }
        word(&mut out, snapshot.evm_word);
        out.push(u8::from(snapshot.summaries.is_some()));
        if let Some(summaries) = snapshot.summaries {
            for summary in summaries {
                word(&mut out, summary.first);
                word(&mut out, summary.second);
                out.extend_from_slice(&summary.block_hash.0);
            }
        }
    }
    map(&mut out, message.peers)?;
    encode_u32(message.random, PayloadOrder::Little, &mut out);
    debug_assert_eq!(out.len(), len);
    Ok(out)
}

/// Exact variant-4 length, including prefix, tag, signer, random and round.
#[must_use]
pub fn acknowledgement_preimage_len(random: u32, round: Round) -> usize {
    50 + encoded_len_u32(random) + encoded_len_u64(round.0)
}

/// Encode variant 4 in signer, random, round order. No outer signature is read.
pub fn acknowledgement_preimage(
    signer: ValidatorAddress,
    random: u32,
    round: Round,
) -> Result<Vec<u8>, PreimageError> {
    let len = acknowledgement_preimage_len(random, round);
    let mut out = begin(4, len)?;
    out.extend_from_slice(&signer.0);
    encode_u32(random, PayloadOrder::Little, &mut out);
    word(&mut out, round.0);
    debug_assert_eq!(out.len(), len);
    Ok(out)
}

fn digest(preimage: Vec<u8>) -> [u8; 32] {
    *node94_action_signable::keccak256(&preimage).as_bytes()
}

/// Hash [`timeout_preimage`] with the credited existing Keccak implementation.
pub fn timeout_digest(
    qc: &Qc,
    round: Round,
    signer: ValidatorAddress,
) -> Result<[u8; 32], PreimageError> {
    Ok(digest(timeout_preimage(qc, round, signer)?))
}

/// Hash [`heartbeat_preimage`] with the credited existing Keccak implementation.
pub fn heartbeat_digest(message: &HeartbeatMessage<'_>) -> Result<[u8; 32], PreimageError> {
    Ok(digest(heartbeat_preimage(message)?))
}

/// Hash [`acknowledgement_preimage`] with the credited existing Keccak implementation.
pub fn acknowledgement_digest(
    signer: ValidatorAddress,
    random: u32,
    round: Round,
) -> Result<[u8; 32], PreimageError> {
    Ok(digest(acknowledgement_preimage(signer, random, round)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_sizing_rejects_overflow_without_allocating() {
        let mut size = isize::MAX as usize;
        assert_eq!(add(&mut size, 1), Err(PreimageError::LengthOverflow));
        let mut size = 1;
        assert_eq!(
            add(&mut size, usize::MAX),
            Err(PreimageError::LengthOverflow)
        );
    }
}
