#![forbid(unsafe_code)]
//! Owned model of the node #115 TWAP-cancel signing-input builder (`0x36aa9a0`).
//!
//! One call maps a valid `twapCancel { a, t }`, the nonce/vault/expiry suffix
//! record and the chain selector to the object the native function returns: the
//! 32-byte inner Keccak-256 digest, the one-byte chain tag and the constant
//! `0x539`. It does not sign, build the outer EIP-712 hash, decode a wire action
//! or execute anything; those happen after this function returns.

/// Keccak-256 rate in bytes (`0x88`, stored at state offset `0xd0`).
pub const RATE: usize = 136;
/// Constant stored at offset `0x38` of the returned record (1337).
pub const RECORD_CONSTANT: u64 = 0x539;
/// Tag byte returned when the selector's low byte is 3.
pub const TAG_SELECTOR_THREE: u8 = 0x61;
/// Tag byte returned for every other selector.
pub const TAG_OTHER: u8 = 0x62;
/// Longest possible preimage: 35-byte cancel map plus 38-byte suffix.
pub const MAX_PREIMAGE: usize = 73;

/// The `twapCancel` action payload: `a` is the asset (u32), `t` the TWAP id (u64).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Cancel {
    pub asset: u32,
    pub twap_id: u64,
}

/// The suffix record read at `rcx` by `0x36aa9a0`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Suffix {
    pub nonce: u64,
    pub vault: Option<[u8; 20]>,
    pub expires_after: Option<u64>,
}

/// The exact bytes the native function feeds to its Keccak update call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Preimage {
    bytes: [u8; MAX_PREIMAGE],
    len: usize,
}

impl Preimage {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    fn push(&mut self, byte: u8) {
        self.bytes[self.len] = byte;
        self.len += 1;
    }

    fn extend(&mut self, data: &[u8]) {
        self.bytes[self.len..self.len + data.len()].copy_from_slice(data);
        self.len += data.len();
    }

    /// MessagePack fixstr; every string on this path is shorter than 32 bytes.
    fn fixstr(&mut self, text: &[u8]) {
        self.push(0xa0 | text.len() as u8);
        self.extend(text);
    }

    /// Smallest-width MessagePack unsigned integer (`0x3d517e0`).
    fn uint(&mut self, n: u64) {
        if n < 128 {
            self.push(n as u8);
        } else if n < 256 {
            self.push(0xcc);
            self.push(n as u8);
        } else if n < 65536 {
            self.push(0xcd);
            self.extend(&(n as u16).to_be_bytes());
        } else if n <= u64::from(u32::MAX) {
            self.push(0xce);
            self.extend(&(n as u32).to_be_bytes());
        } else {
            self.push(0xcf);
            self.extend(&n.to_be_bytes());
        }
    }
}

/// Cancel map (`0x46abec0` in struct-map mode) followed by the suffix.
pub fn preimage(cancel: Cancel, suffix: Suffix) -> Preimage {
    let mut p = Preimage {
        bytes: [0; MAX_PREIMAGE],
        len: 0,
    };
    p.push(0x80 | 3);
    p.fixstr(b"type");
    p.fixstr(b"twapCancel");
    p.fixstr(b"a");
    p.uint(u64::from(cancel.asset));
    p.fixstr(b"t");
    p.uint(cancel.twap_id);
    p.extend(&suffix.nonce.to_be_bytes());
    match suffix.vault {
        Some(vault) => {
            p.push(1);
            p.extend(&vault);
        }
        None => p.push(0),
    }
    if let Some(expiry) = suffix.expires_after {
        p.push(0);
        p.extend(&expiry.to_be_bytes());
    }
    p
}

/// Keccak-256 (domain byte 1) of a message shorter than one rate block.
///
/// Returns `None` for inputs of 136 bytes or more; the native path for those
/// absorbs through permutations and is not part of this reconstruction.
pub fn keccak256_short(data: &[u8]) -> Option<[u8; 32]> {
    if data.len() >= RATE {
        return None;
    }
    let mut block = [0u8; 200];
    block[..data.len()].copy_from_slice(data);
    block[data.len()] ^= 0x01;
    block[RATE - 1] ^= 0x80;
    let mut lanes = [0u64; 25];
    for (lane, chunk) in lanes.iter_mut().zip(block.chunks_exact(8)) {
        *lane = u64::from_le_bytes(chunk.try_into().unwrap());
    }
    permutation::permute(&mut lanes);
    let mut digest = [0u8; 32];
    for (chunk, lane) in digest.chunks_exact_mut(8).zip(&lanes) {
        chunk.copy_from_slice(&lane.to_le_bytes());
    }
    Some(digest)
}

/// What `0x36aa9a0` returns, minus the allocator-owned tag pointer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SigningInput {
    /// The one-byte string held by the record: `0x61` or `0x62`.
    pub tag: u8,
    pub digest: [u8; 32],
}

/// The native chain-tag rule: `cmp bpl,3` looks only at the selector's low byte.
pub fn tag_for_selector(selector: u32) -> u8 {
    if selector as u8 == 3 {
        TAG_SELECTOR_THREE
    } else {
        TAG_OTHER
    }
}

/// The whole function: preimage, digest and tag for one selector.
pub fn signing_input(cancel: Cancel, suffix: Suffix, selector: u32) -> SigningInput {
    let input = preimage(cancel, suffix);
    SigningInput {
        tag: tag_for_selector(selector),
        digest: keccak256_short(input.as_bytes()).expect("preimage is at most 73 bytes"),
    }
}

impl SigningInput {
    /// The 0x58-byte returned record as eleven little-endian words.
    ///
    /// `[1, tag pointer, 1, digest x4, 0x539, 0, 0, 0]`. The pointer is the
    /// address of the freshly allocated one-byte tag string; the caller supplies
    /// it because allocation is not modelled.
    pub fn record_words(&self, tag_address: u64) -> [u64; 11] {
        let mut words = [0u64; 11];
        words[0] = 1;
        words[1] = tag_address;
        words[2] = 1;
        for (word, chunk) in words[3..7].iter_mut().zip(self.digest.chunks_exact(8)) {
            *word = u64::from_le_bytes(chunk.try_into().unwrap());
        }
        words[7] = RECORD_CONSTANT;
        words
    }
}
