//! Cryptographic hashing and filesystem atomic-replace helpers (`l1/src/utils.rs`).
//!
//! Anchored to node #115:
//! - `l1/src/utils.rs:19:42` (`0x38d2ce0`, `0x38d2ef0`, `0x38d3100`, `0x4e36af0`):
//!   MessagePack-named Keccak-256 (`rate = 0x88`, `delim = 0x01`)
//! - `l1/src/utils.rs:28:43` (`0x38d2920`, `0x38d2b00`):
//!   MessagePack-named SHA-256 (`.rodata 0x457ae0..0x457b00` FIPS 180-4 IV)
//! - `l1/src/utils.rs:121:5` (`0x38d7f20`):
//!   `utils_hard_link_and_replace/` same-`(dev, ino)` short-circuit + hard-link & rename

use std::fs;
use std::io;
use std::path::Path;

/// Temp subdirectory prefix observed at `.rodata 0x439e44` in `0x38d7fc7` (`l1/src/utils.rs:121:5`).
pub const HARD_LINK_TEMP_PREFIX: &str = "utils_hard_link_and_replace/";

/// Keccak-256 sponge rate (`0x88` = 136 bytes) initialized at `0x38d2dad` (`l1/src/utils.rs:19:42`).
pub const KECCAK256_RATE: usize = 0x88;

/// Keccak-256 domain-separation byte (`0x01`) initialized at `0x38d2db9` (`l1/src/utils.rs:19:42`).
pub const KECCAK256_DELIM: u8 = 0x01;

/// Exact SHA-256 initial hash values loaded from `.rodata 0x457ae0..0x457b00` at `0x38d299d`.
pub const SHA256_IV: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

const SHA256_K: [u32; 64] = [
    0x428a_2f98, 0x7137_4491, 0xb5c0_fbcf, 0xe9b5_dba5, 0x3956_c25b, 0x59f1_11f1, 0x923f_82a4,
    0xab1c_5ed5, 0xd807_aa98, 0x1283_5b01, 0x2431_85be, 0x550c_7dc3, 0x72be_5d74, 0x80de_b1fe,
    0x9bdc_06a7, 0xc19b_f174, 0xe49b_69c1, 0xefbe_4786, 0x0fc1_9dc6, 0x240c_a1cc, 0x2de9_2c6f,
    0x4a74_84aa, 0x5cb0_a9dc, 0x76f9_88da, 0x983e_5152, 0xa831_c66d, 0xb003_27c8, 0xbf59_7fc7,
    0xc6e0_0bf3, 0xd5a7_9147, 0x06ca_6351, 0x1429_2967, 0x27b7_0a85, 0x2e1b_2138, 0x4d2c_6dfc,
    0x5338_0d13, 0x650a_7354, 0x766a_0abb, 0x81c2_c92e, 0x9272_2c85, 0xa2bf_e8a1, 0xa81a_664b,
    0xc24b_8b70, 0xc76c_51a3, 0xd192_e819, 0xd699_0624, 0xf40e_3585, 0x106a_a070, 0x19a4_c116,
    0x1e37_6c08, 0x2748_774c, 0x34b0_bcb5, 0x391c_0cb3, 0x4ed8_aa4a, 0x5b9c_ca4f, 0x682e_6ff3,
    0x748f_82ee, 0x78a5_636f, 0x84c8_7814, 0x8cc7_0208, 0x90be_fffa, 0xa450_6ceb, 0xbef9_a3f7,
    0xc671_78f2,
];

/// Pure-Rust SHA-256 matching node #115's `l1/src/utils.rs:28` digest step (`0x38d2920`).
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = SHA256_IV;
    let bit_len = (data.len() as u64).wrapping_mul(8);

    let mut padded = Vec::with_capacity((data.len() + 9).div_ceil(64) * 64);
    padded.extend_from_slice(data);
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in padded.chunks_exact(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(SHA256_K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

const KECCAK_RC: [u64; 24] = [
    0x0000_0000_0000_0001, 0x0000_0000_0000_8082, 0x8000_0000_0000_808a, 0x8000_0000_8000_8000,
    0x0000_0000_0000_808b, 0x0000_0000_8000_0001, 0x8000_0000_8000_8081, 0x8000_0000_0000_8009,
    0x0000_0000_0000_008a, 0x0000_0000_0000_0088, 0x0000_0000_8000_8009, 0x0000_0000_8000_000a,
    0x0000_0000_8000_808b, 0x8000_0000_0000_008b, 0x8000_0000_0000_8089, 0x8000_0000_0000_8003,
    0x8000_0000_0000_8002, 0x8000_0000_0000_0080, 0x0000_0000_0000_800a, 0x8000_0000_8000_000a,
    0x8000_0000_8000_8081, 0x8000_0000_0000_8080, 0x0000_0000_8000_0001, 0x8000_0000_8000_8008,
];

const KECCAK_RHO: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

const KECCAK_PI: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

fn keccak_f1600(state: &mut [u64; 25]) {
    for &rc in &KECCAK_RC {
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        for x in 0..5 {
            let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            for y in 0..5 {
                state[x + 5 * y] ^= d;
            }
        }
        let mut current = state[1];
        for i in 0..24 {
            let j = KECCAK_PI[i];
            let next = state[j];
            state[j] = current.rotate_left(KECCAK_RHO[i]);
            current = next;
        }
        for y in 0..5 {
            let row = [
                state[5 * y],
                state[5 * y + 1],
                state[5 * y + 2],
                state[5 * y + 3],
                state[5 * y + 4],
            ];
            for x in 0..5 {
                state[5 * y + x] = row[x] ^ ((!row[(x + 1) % 5]) & row[(x + 2) % 5]);
            }
        }
        state[0] ^= rc;
    }
}

/// Pure-Rust Keccak-256 (`rate = 0x88`, `delim = 0x01`) matching `l1/src/utils.rs:19` (`0x38d2ce0`).
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut state = [0u64; 25];
    let mut offset = 0usize;
    while data.len() - offset >= KECCAK256_RATE {
        for i in 0..(KECCAK256_RATE / 8) {
            let lane = u64::from_le_bytes([
                data[offset + i * 8],
                data[offset + i * 8 + 1],
                data[offset + i * 8 + 2],
                data[offset + i * 8 + 3],
                data[offset + i * 8 + 4],
                data[offset + i * 8 + 5],
                data[offset + i * 8 + 6],
                data[offset + i * 8 + 7],
            ]);
            state[i] ^= lane;
        }
        keccak_f1600(&mut state);
        offset += KECCAK256_RATE;
    }

    let mut block = [0u8; KECCAK256_RATE];
    let rem = data.len() - offset;
    block[..rem].copy_from_slice(&data[offset..]);
    block[rem] ^= KECCAK256_DELIM;
    block[KECCAK256_RATE - 1] ^= 0x80;
    for i in 0..(KECCAK256_RATE / 8) {
        let lane = u64::from_le_bytes([
            block[i * 8],
            block[i * 8 + 1],
            block[i * 8 + 2],
            block[i * 8 + 3],
            block[i * 8 + 4],
            block[i * 8 + 5],
            block[i * 8 + 6],
            block[i * 8 + 7],
        ]);
        state[i] ^= lane;
    }
    keccak_f1600(&mut state);

    let mut out = [0u8; 32];
    for i in 0..4 {
        out[i * 8..i * 8 + 8].copy_from_slice(&state[i].to_le_bytes());
    }
    out
}

/// Outcome of [`hard_link_and_replace`] (`l1/src/utils.rs:121:5`, `0x38d7f20`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HardLinkOutcome {
    /// Source and destination already share the exact same `(dev, ino)` inode (`0x38d7f86..0x38d7f96`).
    AlreadySameInode,
    /// Created temp hard link under `utils_hard_link_and_replace/` and atomically renamed into `dst`.
    Replaced,
}

/// Reconstructs `l1/src/utils.rs:121:5` (`0x38d7f20`):
/// if `src` and `dst` already have identical `(dev, ino)` metadata, returns immediately;
/// otherwise hard-links `src` into `<temp_root>/utils_hard_link_and_replace/<nonce>` and
/// atomically renames it onto `dst`.
#[cfg(unix)]
pub fn hard_link_and_replace(
    src: &Path,
    dst: &Path,
    temp_root: &Path,
    unique_id: &str,
) -> io::Result<HardLinkOutcome> {
    use std::os::unix::fs::MetadataExt;

    let src_meta = fs::metadata(src)?;
    if let Ok(dst_meta) = fs::metadata(dst) {
        if src_meta.dev() == dst_meta.dev() && src_meta.ino() == dst_meta.ino() {
            return Ok(HardLinkOutcome::AlreadySameInode);
        }
    }

    let stage_dir = temp_root.join(HARD_LINK_TEMP_PREFIX);
    fs::create_dir_all(&stage_dir)?;
    let tmp_path = stage_dir.join(unique_id);
    let _ = fs::remove_file(&tmp_path);
    fs::hard_link(src, &tmp_path)?;
    if let Err(err) = fs::rename(&tmp_path, dst) {
        let _ = fs::remove_file(&tmp_path);
        return Err(err);
    }
    Ok(HardLinkOutcome::Replaced)
}
