//! The bounded node #94 checkpoint hash helper at `0x394b410..0x394b657`.
//!
//! The caller supplies an already canonically serialized state prefix. This
//! module does not serialize or validate state, and received snapshot bytes are
//! not necessarily that prefix. It appends the named MessagePack encoding of
//! three records before computing an ordinary unkeyed BLAKE3 digest.
//!
//! Evidence is bound to node #94 SHA-256
//! `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
//! The pure Rust BLAKE3 backend is an independent implementation choice, not a
//! claim about the target's machine code or original dependency graph.

use crate::greeting::reply::FixedRecord;

/// Encode accounts, contracts and storage records in that order.
///
/// Each named MessagePack map contains `n_elements` (`first`), `n_bytes`
/// (`second`) and `hash` (`bytes`). All 2,048 bytes are preserved regardless of
/// the counters. Integers use their shortest unsigned encoding. The result
/// contains only this map, with no enclosing length prefix or trailing bytes.
pub fn encode_records(records: &[FixedRecord; 3]) -> Vec<u8> {
    let mut out = Vec::with_capacity(6325);
    out.push(0x83);
    for (key, record) in [
        b"\xadaccounts_hash".as_slice(),
        b"\xaecontracts_hash".as_slice(),
        b"\xacstorage_hash".as_slice(),
    ]
    .into_iter()
    .zip(records)
    {
        out.extend_from_slice(key);
        out.extend_from_slice(b"\x83\xaan_elements");
        encode_u64(record.first, &mut out);
        out.extend_from_slice(b"\xa7n_bytes");
        encode_u64(record.second, &mut out);
        out.extend_from_slice(b"\xa4hash\xc5\x08\x00");
        out.extend_from_slice(&record.bytes);
    }
    out
}

/// Hash an already canonically serialized state prefix followed by the records.
///
/// The caller must produce `serialized_state` using the required state
/// serializer; this function does not establish that it encodes valid state.
/// It inserts no separator or length between that prefix and [`encode_records`].
/// A digest alone does not establish checkpoint validity or peer acceptance.
pub fn compute(serialized_state: &[u8], records: &[FixedRecord; 3]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(serialized_state);
    hasher.update(&encode_records(records));
    *hasher.finalize().as_bytes()
}

fn encode_u64(value: u64, out: &mut Vec<u8>) {
    match value {
        0..=0x7f => out.push(value as u8),
        0x80..=0xff => out.extend_from_slice(&[0xcc, value as u8]),
        0x100..=0xffff => {
            out.push(0xcd);
            out.extend_from_slice(&(value as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(0xce);
            out.extend_from_slice(&(value as u32).to_be_bytes());
        }
        _ => {
            out.push(0xcf);
            out.extend_from_slice(&value.to_be_bytes());
        }
    }
}
