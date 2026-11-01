use hl_bincode_varint::{encode_u64, PayloadOrder};

use crate::{Qc, ValidatorAddress};

const PREFIX: &[u8; 29] = b"Hyperliquid Consensus Payload";

/// Encode node #94's variant-1 QC-vote signing preimage.
///
/// The order is the 29-byte prefix, tag 1, signer20, three little-endian
/// variable-width u64 values (version, start round, round), then block hash32.
/// The result is 85..=109 bytes. The supplied signer is included even when it
/// does not occur in `qc.votes`; membership and authentication are separate.
/// Votes, signatures, padding, and the nearby native logging label are absent.
///
/// This safe value API implements the finite contract in
/// `RE-008-qc-vote-preimage-94`; it is not a serializer for an entire QC or a
/// claim about the native Rust ABI or the other four digest variants.
#[must_use]
pub fn qc_vote_preimage(qc: &Qc, signer: ValidatorAddress) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(109);
    bytes.extend_from_slice(PREFIX);
    bytes.push(1);
    bytes.extend_from_slice(&signer.0);
    for word in [qc.hardfork.version, qc.hardfork.start_round.0, qc.round.0] {
        encode_u64(word, PayloadOrder::Little, &mut bytes);
    }
    bytes.extend_from_slice(&qc.block_hash.0);
    bytes
}

/// Hash [`qc_vote_preimage`] with the existing independent Keccak-256 component.
///
/// The native output correspondence credits the previously identified shared
/// Keccak core; this packet does not add a formal permutation-equivalence proof.
/// Producing this digest does not validate a QC, recover a signer, or authenticate
/// a block identity. No key or signature operation is performed.
#[must_use]
pub fn qc_vote_digest(qc: &Qc, signer: ValidatorAddress) -> [u8; 32] {
    *node94_action_signable::keccak256(&qc_vote_preimage(qc, signer)).as_bytes()
}
