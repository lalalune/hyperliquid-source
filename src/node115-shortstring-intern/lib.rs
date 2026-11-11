//! Node #115 (`a6e2897c...5301`) name-to-key function at `0x1546aa0` (`base/src/short_string.rs`)
//! and the row builder at `0x155cd10` that consumes it (`base/src/cid.rs`). Static reconstruction:
//! the target was never run, and nothing here is a comparison with it.
//!
//! `&str` in, `u128` key out. Names of at most 16 bytes are packed little-endian (the 89-byte fold
//! at `0x15472b0`, described by `RE-001-node115-shortstring-le-u128-fold`). A longer name gets ten
//! letters, `'A' + SipHash-1-3(name || 0xff || i as i32 LE) % 26` for `i = 0..10`, which are packed
//! the same way; the result for a name is remembered in a process-wide map that stops taking new
//! names once it holds 100,000 entries. Std only; the map's own hasher is not modelled.
use std::collections::HashMap;

/// `0x1546abe`: `cmp rsi,0x10; jbe` (bytes, not characters).
pub const SHORT_MAX_LEN: usize = 16;
/// `0x1546ca4`: the generator's index range is `0..0xa` (`movabs rax,0xa00000000`).
pub const GENERATED_LEN: usize = 10;
/// `0x155cf75`: `mov BYTE PTR [rsp+0x8],0xff`, written after the name bytes.
pub const TERMINATOR: u8 = 0xff;
/// `0x155cf93`: the index is written as 4 bytes (`edx = 4`), an `i32`.
pub const INDEX_WIDTH: usize = 4;
/// `0x155d094`: `0x4ec4ec4ec4ec4ec5` is the reciprocal for `% 26`.
pub const ALPHABET_LEN: u64 = 26;
/// `0x155d0bf`: `add r14b,0x41`.
pub const ALPHABET_BASE: u8 = 0x41;
/// `0x1546d9a`: `cmp r15,0x1869f; ja` skips the insert, so a new name is stored only while the map holds at most this many.
pub const CACHE_INSERT_MAX_LEN: usize = 99_999;
/// `0x155cf10..0x155cf47`: the four SipHash words with an all-zero key, in the struct order v0, v2, v1, v3.
pub const SIP_INIT: [u64; 4] = [0x736f6d6570736575, 0x6c7967656e657261, 0x646f72616e646f6d, 0x7465646279746573];
/// Four `rol 0xd` rounds in `0x155cfce..0x155d07d`: one per message block plus three after the `0xff` xor.
pub const SIP_C_ROUNDS: u32 = 1;
pub const SIP_D_ROUNDS: u32 = 3;

/// The fold at `0x15472b0` panics (arithmetic overflow) when a byte at index 16 or later is nonzero.
#[derive(Debug, PartialEq, Eq)]
pub struct FoldOverflow;

/// Little-endian pack of `bytes` into a `u128`, with the overflow rule of `0x15472b0`.
pub fn fold_le_u128(bytes: &[u8]) -> Result<u128, FoldOverflow> {
    let mut acc: u128 = 0;
    for &b in bytes.iter().rev() {
        if acc >> 120 != 0 {
            return Err(FoldOverflow);
        }
        acc = (acc << 8) | u128::from(b);
    }
    Ok(acc)
}

/// Streaming SipHash-1-3 with a zero key, the shape of the `write` body at `0x15709f0`
/// (eight-byte blocks, a pending tail, a running byte count) and the finish inlined at `0x155cfa3`.
pub struct SipHasher13 {
    v: [u64; 4],
    length: u64,
    pending: [u8; 8],
    npending: usize,
}

fn sip_round(v: &mut [u64; 4]) {
    v[0] = v[0].wrapping_add(v[1]);
    v[1] = v[1].rotate_left(13) ^ v[0];
    v[0] = v[0].rotate_left(32);
    v[2] = v[2].wrapping_add(v[3]);
    v[3] = v[3].rotate_left(16) ^ v[2];
    v[0] = v[0].wrapping_add(v[3]);
    v[3] = v[3].rotate_left(21) ^ v[0];
    v[2] = v[2].wrapping_add(v[1]);
    v[1] = v[1].rotate_left(17) ^ v[2];
    v[2] = v[2].rotate_left(32);
}

impl SipHasher13 {
    pub fn new_zero_key() -> Self {
        // SIP_INIT is stored v0, v2, v1, v3 (the struct order of the binary); the algorithm names are v0..v3.
        let [v0, v2, v1, v3] = SIP_INIT;
        SipHasher13 { v: [v0, v1, v2, v3], length: 0, pending: [0; 8], npending: 0 }
    }

    fn block(&mut self, m: u64) {
        self.v[3] ^= m;
        for _ in 0..SIP_C_ROUNDS {
            sip_round(&mut self.v);
        }
        self.v[0] ^= m;
    }

    pub fn write(&mut self, bytes: &[u8]) {
        self.length = self.length.wrapping_add(bytes.len() as u64);
        for &b in bytes {
            self.pending[self.npending] = b;
            self.npending += 1;
            if self.npending == 8 {
                let m = u64::from_le_bytes(self.pending);
                self.npending = 0;
                self.block(m);
            }
        }
    }

    pub fn finish(&self) -> u64 {
        let mut tail = [0u8; 8];
        tail[..self.npending].copy_from_slice(&self.pending[..self.npending]);
        let b = (self.length << 56) | u64::from_le_bytes(tail);
        let mut v = self.v;
        v[3] ^= b;
        for _ in 0..SIP_C_ROUNDS {
            sip_round(&mut v);
        }
        v[0] ^= b;
        v[2] ^= 0xff;
        for _ in 0..SIP_D_ROUNDS {
            sip_round(&mut v);
        }
        v[0] ^ v[1] ^ v[2] ^ v[3]
    }
}

/// The ten letters made for a long name (`0x155ced0`): `i = 0..10`, hash of `name`, `0xff`, `i` as four
/// little-endian bytes (three separate writes, as the binary makes them).
pub fn generated_name(name: &[u8]) -> [u8; GENERATED_LEN] {
    let mut out = [0u8; GENERATED_LEN];
    for (i, slot) in out.iter_mut().enumerate() {
        let mut h = SipHasher13::new_zero_key();
        h.write(name);
        h.write(&[TERMINATOR]);
        h.write(&(i as i32).to_le_bytes()[..INDEX_WIDTH]);
        *slot = ALPHABET_BASE + (h.finish() % ALPHABET_LEN) as u8;
    }
    out
}

/// Which branch of `0x1546aa0` produced a key. This is the model's own report, not a node output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Path {
    /// at most 16 bytes: direct fold, the map is not touched
    Short,
    /// map hit: the stored key is returned
    Hit,
    /// miss, generated, stored (the map held at most 99,999 entries)
    MissInserted,
    /// miss, generated, not stored (the map already held 100,000)
    MissNotInserted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Keyed {
    pub key: u128,
    pub path: Path,
}

/// The process-wide name map of `0x1546aa0`, one value here. Single-threaded: the size test happens
/// before the node takes its write lock, so with threads the cap is not a hard bound (not modelled).
#[derive(Clone, Default)]
pub struct KeyCache {
    map: HashMap<Vec<u8>, u128>,
}

impl KeyCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn key_for(&mut self, name: &str) -> Keyed {
        let bytes = name.as_bytes();
        if bytes.len() <= SHORT_MAX_LEN {
            let key = fold_le_u128(bytes).expect("a name of at most 16 bytes always folds");
            return Keyed { key, path: Path::Short };
        }
        if let Some(&key) = self.map.get(bytes) {
            return Keyed { key, path: Path::Hit };
        }
        let key = fold_le_u128(&generated_name(bytes)).expect("ten bytes always fold");
        if self.map.len() <= CACHE_INSERT_MAX_LEN {
            self.map.insert(bytes.to_vec(), key);
            Keyed { key, path: Path::MissInserted }
        } else {
            Keyed { key, path: Path::MissNotInserted }
        }
    }
}

/// `0x155cdf0` and `0x155cdf7`: the row stores a 16-byte block then a dword at `+0x10`, 20 bytes after the u128 key.
pub const ROW_VALUE_LEN: usize = 20;

/// One output row of `0x155cd10`: the key, then the 20-byte value from the separate parser.
#[derive(Debug, PartialEq, Eq)]
pub struct CidRow {
    pub key: u128,
    pub value: [u8; ROW_VALUE_LEN],
}

/// The parser failed for item `index` (the node unwraps it and panics). The key call for that item
/// ran before the parser, so `cache` holds its name only if that call stored it (a long name
/// already present, or a miss while the map held at most 99,999 entries).
#[derive(Debug, PartialEq, Eq)]
pub struct RowError<E> {
    pub index: usize,
    pub source: E,
}

/// `0x155cd10` for a given item order: for each `(name, text)` the name goes through the key
/// function first (`call 0x1546aa0` at `0x155cdab`), then `text` goes to the 20-byte parser
/// (`0x155cdc2`, GOT `0x64e0b88`, not reconstructed here: `parse20` is supplied by the caller).
/// A parse error stops the build; rows made so far are dropped.
pub fn build_rows<'a, E>(
    cache: &mut KeyCache,
    items: impl IntoIterator<Item = (&'a str, &'a str)>,
    mut parse20: impl FnMut(&str) -> Result<[u8; ROW_VALUE_LEN], E>,
) -> Result<Vec<CidRow>, RowError<E>> {
    let mut rows = Vec::new();
    for (index, (name, text)) in items.into_iter().enumerate() {
        let key = cache.key_for(name).key;
        match parse20(text) {
            Ok(value) => rows.push(CidRow { key, value }),
            Err(source) => return Err(RowError { index, source }),
        }
    }
    Ok(rows)
}
