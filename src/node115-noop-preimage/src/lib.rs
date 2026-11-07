#![forbid(unsafe_code)]
//! Owned unsigned Noop preimage at the node #115 serializer boundary.
//!
//! This API models normal successful serialization of raw action tag 0x86.
//! It does not decode an action, authorize it, obtain a nonce, or sign anything.

/// The complete serialized bytes passed to the inner digest updater.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Preimage {
    bytes: [u8; 49],
    len: usize,
}

impl Preimage {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

/// Build the observed Noop map followed by the existing suffix contract.
///
/// The native valid present tags are 1; `Option` excludes malformed tag values.
/// The optional expiry follows a zero marker, including when a vault is present.
/// Domain/chain selection happens after the inner digest and is not an input
/// to these bytes. The output owns its bytes and allocates no heap storage.
pub fn preimage(nonce: u64, vault: Option<[u8; 20]>, expires_after: Option<u64>) -> Preimage {
    let mut result = Preimage {
        bytes: [0; 49],
        len: 11,
    };
    result.bytes[..11].copy_from_slice(b"\x81\xa4type\xa4noop");
    result.bytes[11..19].copy_from_slice(&nonce.to_be_bytes());
    result.len = 20;
    if let Some(address) = vault {
        result.bytes[19] = 1;
        result.bytes[20..40].copy_from_slice(&address);
        result.len = 40;
    }
    if let Some(expiry) = expires_after {
        // The following marker is already zero in the owned backing array.
        let at = result.len;
        result.bytes[at + 1..at + 9].copy_from_slice(&expiry.to_be_bytes());
        result.len += 9;
    }
    result
}

/// The 32-byte inner digest of this bounded complete preimage.
///
/// Every constructible preimage is shorter than the observed 136-byte rate:
/// exactly one padded block and one permutation are needed. This composes the
/// previously implemented permutation with the selected normal absorb/finalize
/// path; it is not a general streaming hash or an outer signing-domain hash.
pub fn inner_digest(input: &Preimage) -> [u8; 32] {
    let mut bytes = [0u8; 200];
    bytes[..input.len].copy_from_slice(input.as_bytes());
    bytes[input.len] ^= 1;
    bytes[135] ^= 0x80;
    let mut lanes = [0u64; 25];
    for (lane, block) in lanes.iter_mut().zip(bytes.chunks_exact(8)) {
        *lane = u64::from_le_bytes(block.try_into().unwrap());
    }
    permutation::permute(&mut lanes);
    let mut digest = [0u8; 32];
    for (block, lane) in digest.chunks_exact_mut(8).zip(&lanes) {
        block.copy_from_slice(&lane.to_le_bytes());
    }
    digest
}
