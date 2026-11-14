//! The digest builder `0x57e8d40` for message variant 1, the only variant the verifier hands to the check:
//! Keccak-256 over `"Hyperliquid Consensus Payload"` followed by the serialized message.
//!
//! Message `{variant, frame pointer}` is serialized by `0x5823db0`: the variant selects an arm through the
//! jump tables `0x935c44` (size pass) and `0x935c58` (write pass); arm 1 writes the byte `0x01` and calls
//! `0x5966b90`, which writes, in this order: the signer address at frame `+0x48` (20 raw bytes, `0x58221e0`),
//! the five words at `+0x20`, `+0x28`, `+0x30`, `+0x38`, `+0x40` (unsigned 64 bit varints, `0x5822910`) and
//! the 32 hash bytes at `+0x00` (raw, `0x5822260`). The integer encoding is a varint: below 251 one byte,
//! below 2^16 the byte `0xfb` and two bytes, below 2^32 `0xfc` and four, else `0xfd` and eight, all little
//! endian. The two prefix pieces are joined by `0x5b3df10` and hashed with [`crate::keccak`]. The other four
//! arms of the message serializer, and the size pass `0x5966cd0` that only sets the buffer capacity, were not
//! read; the clock reads at the start of the builder (`0x5c842e0`, `0x5c84210`) do not feed the hash.
//!
//! Source of the facts: `research/work-items/RE-008-node115-nested-certificate-decision/relations-digest.tsv`
//! (DB1..DB6, MS1, MS2, VS1, FB1, PV1..PV4, PA1, PA2, CC1), each row pinned to instruction text.

use crate::keccak::Hasher;
use crate::signer::VoteFrame;

/// The 29 bytes at `0x936313..0x936330` (data-pins.tsv), copied by `0x57e8d40` in front of the message.
pub const PREFIX: &[u8; 29] = b"Hyperliquid Consensus Payload";

/// The only message variant read: the first word of the message, written as the byte `0x01`.
pub const VARIANT: u64 = 1;

/// `0x5822910`: unsigned 64 bit varint, written by the base tree's `node115-varint-buffer-writer`
/// (`RE-005-varint-buffer-writer-115`, path dependency). That writer reports an allocation refusal as an
/// error value; the native path goes to the fatal allocation handler and does not return, so this call
/// panics instead (the plain `Vec` growth used before this round aborted). Output bytes are the same.
pub fn put_varint(out: &mut Vec<u8>, v: u64) {
    node115_varint_buffer_writer::write_u64(out, v).expect("allocation refused while writing a varint");
}

/// `0x5823db0` arm 1 with `0x5966b90`: the serialized message of variant 1.
pub fn serialize_message(frame: &VoteFrame) -> Vec<u8> {
    let mut out = vec![0x01];
    out.extend_from_slice(&frame.signer);
    for w in [frame.pair[0], frame.pair[1], frame.f30, frame.f38, frame.f40] {
        put_varint(&mut out, w);
    }
    out.extend_from_slice(&frame.hash);
    out
}

/// The bytes that `0x57e8d40` hashes: the prefix, then the serialized message (`0x5b3df10`).
pub fn preimage(frame: &VoteFrame) -> Vec<u8> {
    let mut out = PREFIX.to_vec();
    out.extend_from_slice(&serialize_message(frame));
    out
}

/// `0x57e8d40(out, message {1, frame})`: the 32 byte digest.
pub fn digest(frame: &VoteFrame) -> [u8; 32] {
    let mut h = Hasher::keccak256();
    h.update(&preimage(frame));
    h.finalize()
}
