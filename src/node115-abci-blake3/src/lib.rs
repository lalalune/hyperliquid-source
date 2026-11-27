#![no_std]
#![forbid(unsafe_code)]
//! Standard unkeyed BLAKE3 implementation matching node #115's state-root digest
//! (`0x548dad0 -> slot 0x64e7820 -> 0x41c5140 -> 0x160b3a0 / 0x160bcd0`, IV at `.rodata 0x457ae0`).

extern crate alloc;

use alloc::vec::Vec;

pub const BLOCK_LEN: usize = 64;
pub const CHUNK_LEN: usize = 1024;

pub const CHUNK_START: u32 = 1 << 0;
pub const CHUNK_END: u32 = 1 << 1;
pub const PARENT: u32 = 1 << 2;
pub const ROOT: u32 = 1 << 3;

/// Standard BLAKE3 IV verified at `.rodata 0x457ae0..0x457b00` in node #115.
pub const IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

const MSG_PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

#[inline]
fn g(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, mx: u32, my: u32) {
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(mx);
    state[d] = (state[d] ^ state[a]).rotate_right(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(12);
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(my);
    state[d] = (state[d] ^ state[a]).rotate_right(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(7);
}

fn round(state: &mut [u32; 16], m: &[u32; 16]) {
    // Columns
    g(state, 0, 4, 8, 12, m[0], m[1]);
    g(state, 1, 5, 9, 13, m[2], m[3]);
    g(state, 2, 6, 10, 14, m[4], m[5]);
    g(state, 3, 7, 11, 15, m[6], m[7]);
    // Diagonals
    g(state, 0, 5, 10, 15, m[8], m[9]);
    g(state, 1, 6, 11, 12, m[10], m[11]);
    g(state, 2, 7, 8, 13, m[12], m[13]);
    g(state, 3, 4, 9, 14, m[14], m[15]);
}

fn permute(m: &mut [u32; 16]) {
    let mut permuted = [0u32; 16];
    for (i, &src) in MSG_PERMUTATION.iter().enumerate() {
        permuted[i] = m[src];
    }
    *m = permuted;
}

fn compress(
    chaining_value: &[u32; 8],
    block_words: &[u32; 16],
    counter: u64,
    block_len: u32,
    flags: u32,
) -> [u32; 16] {
    let mut state = [
        chaining_value[0],
        chaining_value[1],
        chaining_value[2],
        chaining_value[3],
        chaining_value[4],
        chaining_value[5],
        chaining_value[6],
        chaining_value[7],
        IV[0],
        IV[1],
        IV[2],
        IV[3],
        counter as u32,
        (counter >> 32) as u32,
        block_len,
        flags,
    ];
    let mut block = *block_words;
    for r in 0..7 {
        round(&mut state, &block);
        if r < 6 {
            permute(&mut block);
        }
    }
    for i in 0..8 {
        state[i] ^= state[i + 8];
        state[i + 8] ^= chaining_value[i];
    }
    state
}

fn first_8_words(out: [u32; 16]) -> [u32; 8] {
    [
        out[0], out[1], out[2], out[3], out[4], out[5], out[6], out[7],
    ]
}

fn words_from_le_bytes(bytes: &[u8; 64]) -> [u32; 16] {
    let mut words = [0u32; 16];
    for (i, chunk) in bytes.chunks_exact(4).enumerate() {
        words[i] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    words
}

#[derive(Clone)]
struct Output {
    input_cv: [u32; 8],
    block_words: [u32; 16],
    counter: u64,
    block_len: u32,
    flags: u32,
}

impl Output {
    fn chaining_value(&self) -> [u32; 8] {
        first_8_words(compress(
            &self.input_cv,
            &self.block_words,
            self.counter,
            self.block_len,
            self.flags,
        ))
    }

    fn root_hash_32(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        self.root_output_bytes(&mut out);
        out
    }

    /// Standard BLAKE3 extendable-output function (XOF) matching node #115 `0x160ab60`/`0x1609e70`
    /// (`ROOT` flag `0x08`, incrementing 64-byte `output_block_counter`).
    fn root_output_bytes(&self, out_slice: &mut [u8]) {
        for (output_block_counter, out_block) in (0_u64..).zip(out_slice.chunks_mut(BLOCK_LEN)) {
            let words = compress(
                &self.input_cv,
                &self.block_words,
                output_block_counter,
                self.block_len,
                self.flags | ROOT,
            );
            for (word, out_word) in words.iter().zip(out_block.chunks_mut(4)) {
                out_word.copy_from_slice(&word.to_le_bytes()[..out_word.len()]);
            }
        }
    }
}

#[derive(Clone)]
struct ChunkState {
    cv: [u32; 8],
    chunk_counter: u64,
    block: [u8; BLOCK_LEN],
    block_len: u8,
    blocks_compressed: u8,
    flags: u32,
}

impl ChunkState {
    fn new(key: [u32; 8], chunk_counter: u64, flags: u32) -> Self {
        Self {
            cv: key,
            chunk_counter,
            block: [0; BLOCK_LEN],
            block_len: 0,
            blocks_compressed: 0,
            flags,
        }
    }

    fn len(&self) -> usize {
        BLOCK_LEN * (self.blocks_compressed as usize) + (self.block_len as usize)
    }

    fn start_flag(&self) -> u32 {
        if self.blocks_compressed == 0 {
            CHUNK_START
        } else {
            0
        }
    }

    fn update(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            if self.block_len as usize == BLOCK_LEN {
                let words = words_from_le_bytes(&self.block);
                self.cv = first_8_words(compress(
                    &self.cv,
                    &words,
                    self.chunk_counter,
                    BLOCK_LEN as u32,
                    self.flags | self.start_flag(),
                ));
                self.blocks_compressed += 1;
                self.block = [0; BLOCK_LEN];
                self.block_len = 0;
            }
            let want = BLOCK_LEN - self.block_len as usize;
            let take = want.min(input.len());
            self.block[self.block_len as usize..self.block_len as usize + take]
                .copy_from_slice(&input[..take]);
            self.block_len += take as u8;
            input = &input[take..];
        }
    }

    fn output(&self) -> Output {
        Output {
            input_cv: self.cv,
            block_words: words_from_le_bytes(&self.block),
            counter: self.chunk_counter,
            block_len: u32::from(self.block_len),
            flags: self.flags | self.start_flag() | CHUNK_END,
        }
    }
}

fn parent_output(left_cv: [u32; 8], right_cv: [u32; 8], key: [u32; 8], flags: u32) -> Output {
    let mut block_words = [0u32; 16];
    block_words[..8].copy_from_slice(&left_cv);
    block_words[8..].copy_from_slice(&right_cv);
    Output {
        input_cv: key,
        block_words,
        counter: 0,
        block_len: BLOCK_LEN as u32,
        flags: PARENT | flags,
    }
}

/// Incremental standard unkeyed BLAKE3 hasher matching node #115 `0x41c5140`.
#[derive(Clone)]
pub struct Blake3Hasher {
    chunk_state: ChunkState,
    key: [u32; 8],
    cv_stack: [[u32; 8]; 54],
    cv_stack_len: u8,
    flags: u32,
}

impl Default for Blake3Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Blake3Hasher {
    pub fn new() -> Self {
        Self {
            chunk_state: ChunkState::new(IV, 0, 0),
            key: IV,
            cv_stack: [[0; 8]; 54],
            cv_stack_len: 0,
            flags: 0,
        }
    }

    fn push_stack(&mut self, cv: [u32; 8]) {
        self.cv_stack[self.cv_stack_len as usize] = cv;
        self.cv_stack_len += 1;
    }

    fn pop_stack(&mut self) -> [u32; 8] {
        self.cv_stack_len -= 1;
        self.cv_stack[self.cv_stack_len as usize]
    }

    fn add_chunk_chaining_value(&mut self, mut new_cv: [u32; 8], mut total_chunks: u64) {
        while total_chunks & 1 == 0 {
            let left = self.pop_stack();
            new_cv = parent_output(left, new_cv, self.key, self.flags).chaining_value();
            total_chunks >>= 1;
        }
        self.push_stack(new_cv);
    }

    pub fn update(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            if self.chunk_state.len() == CHUNK_LEN {
                let chunk_cv = self.chunk_state.output().chaining_value();
                let total_chunks = self.chunk_state.chunk_counter + 1;
                self.add_chunk_chaining_value(chunk_cv, total_chunks);
                self.chunk_state = ChunkState::new(self.key, total_chunks, self.flags);
            }
            let want = CHUNK_LEN - self.chunk_state.len();
            let take = want.min(input.len());
            self.chunk_state.update(&input[..take]);
            input = &input[take..];
        }
    }

    fn final_output(&self) -> Output {
        let mut output = self.chunk_state.output();
        let mut parent_nodes_remaining = self.cv_stack_len as usize;
        while parent_nodes_remaining > 0 {
            parent_nodes_remaining -= 1;
            output = parent_output(
                self.cv_stack[parent_nodes_remaining],
                output.chaining_value(),
                self.key,
                self.flags,
            );
        }
        output
    }

    pub fn finalize(&self) -> [u8; 32] {
        self.final_output().root_hash_32()
    }

    /// Fill `out` with standard BLAKE3 XOF output bytes (used by node #115 `LtHash` at `0x36c6100` for `0x800` B).
    pub fn finalize_xof_into(&self, out: &mut [u8]) {
        self.final_output().root_output_bytes(out);
    }
}

/// One-shot standard unkeyed BLAKE3 hash matching node #115's `0x41c5140`.
pub fn blake3_hash(input: &[u8]) -> [u8; 32] {
    let mut hasher = Blake3Hasher::new();
    hasher.update(input);
    hasher.finalize()
}

/// One-shot standard unkeyed BLAKE3 XOF matching node #115's `0x36c6100` (`finalize_xof().fill`).
pub fn blake3_xof(input: &[u8], out: &mut [u8]) {
    let mut hasher = Blake3Hasher::new();
    hasher.update(input);
    hasher.finalize_xof_into(out);
}

/// Compute the exact node #115 leaf-mode digest (`0x41c51be..0x41c5220`):
/// MessagePack `str8(66)` `"0x" || lowercase_hex(digest)` hashed with BLAKE3.
pub fn compute_leaf_root(leaf_digest: &[u8; 32]) -> [u8; 32] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut buf = [0u8; 68];
    buf[0] = 0xd9;
    buf[1] = 0x42;
    buf[2] = b'0';
    buf[3] = b'x';
    for (i, &b) in leaf_digest.iter().enumerate() {
        buf[4 + i * 2] = HEX[(b >> 4) as usize];
        buf[5 + i * 2] = HEX[(b & 0x0f) as usize];
    }
    blake3_hash(&buf)
}

/// Compute the exact node #115 state root for any MessagePack-encoded reduction tree preimage.
pub fn compute_preimage_root(preimage: &[u8]) -> [u8; 32] {
    blake3_hash(preimage)
}

/// Helper to format a 32-byte digest as `"0x..."` lowercase hex.
pub fn format_hex_0x(digest: &[u8; 32]) -> Vec<u8> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = Vec::with_capacity(66);
    out.extend_from_slice(b"0x");
    for &b in digest {
        out.push(HEX[(b >> 4) as usize]);
        out.push(HEX[(b & 0x0f) as usize]);
    }
    out
}
