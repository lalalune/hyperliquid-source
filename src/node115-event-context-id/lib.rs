//! Node #115 `0x421dc00`: a 32-byte event context identifier from a mode byte
//! and three `u64` values, plus its spot-deploy call site `0x2c574be`.
//!
//! Static reconstruction. Nothing here ran or emulated the node. The unreachable
//! error paths of the native code (allocation failure in the `Vec` that holds the
//! ABI or MessagePack bytes, an `unwrap` panic at `l1/utils.rs:19:42`) are not
//! modelled: every input has a result, as long as allocation succeeds.
//!
//! Shape of the native function (arguments `out, mode, a, b, c`):
//! 1. `select_source` picks one of three ways to make 32 base bytes.
//! 2. `Source::Arithmetic` mixes `a`, `b`, `c` with wrapping multiply/add; the other
//!    two hash a preimage with Keccak-256: three big-endian 32-byte words (ABI),
//!    or a three-element MessagePack array of minimal-width unsigned integers.
//! 3. `overlay_tail` then overwrites the base bytes from offset 10 with
//!    `len || big-endian a` and `len || big-endian b`, and with `len || c` only
//!    when it still fits in the 32 bytes. The result is therefore NOT the bare
//!    digest.
#![no_std]
#![forbid(unsafe_code)]

use node115_event_context_permutation::permute;

const MULTIPLIER: u64 = 0xf135_7aea_2e62_a9c5;
const WORD_SEEDS: [u64; 4] = [
    0x89ab_d751_7315_4e28,
    0xea62_407f_f1ea_5bb8,
    0xb182_5c50_e63c_e358,
    0x78c3_727a_7176_2f98,
];
const WORD_ROTATE: u32 = 20;
// Mode 2: a > ARITH_ABOVE is arithmetic, else a >= PACKED_FROM is MessagePack, else ABI.
const MODE2_ARITH_ABOVE: u64 = 0x1906_7a34;
const MODE2_PACKED_FROM: u64 = 0x0df5_9bc0;
// Mode above 2: a > ARITH_ABOVE is arithmetic, else a <= ABI_UP_TO is ABI, else MessagePack.
const LATER_ARITH_ABOVE: u64 = 0x2a16_6de8;
const LATER_ABI_UP_TO: u64 = 0x0d37_7be0;
const OVERLAY_START: usize = 10;
const RATE: usize = 136;
const KECCAK_DELIMITER: u8 = 0x01;

/// How the 32 base bytes are produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    Arithmetic,
    Abi,
    MessagePack,
}

/// Branch choice of `0x421dc00` (`cmp sil,2`, then thresholds on `a`).
pub fn select_source(mode: u8, a: u64) -> Source {
    if mode < 2 {
        return Source::Arithmetic;
    }
    if mode == 2 {
        if a > MODE2_ARITH_ABOVE {
            Source::Arithmetic
        } else if a >= MODE2_PACKED_FROM {
            Source::MessagePack
        } else {
            Source::Abi
        }
    } else if a > LATER_ARITH_ABOVE {
        Source::Arithmetic
    } else if a <= LATER_ABI_UP_TO {
        Source::Abi
    } else {
        Source::MessagePack
    }
}

/// Arithmetic branch: four words, each `rotl20((seed*K + c + s) * K)` written
/// big-endian, where `s = (a*K + b) * K`, all wrapping.
pub fn arithmetic_words(a: u64, b: u64, c: u64) -> [u8; 32] {
    let shared = a.wrapping_mul(MULTIPLIER).wrapping_add(b).wrapping_mul(MULTIPLIER);
    let mut out = [0u8; 32];
    for (chunk, seed) in out.chunks_exact_mut(8).zip(WORD_SEEDS) {
        let word = seed
            .wrapping_mul(MULTIPLIER)
            .wrapping_add(c)
            .wrapping_add(shared)
            .wrapping_mul(MULTIPLIER)
            .rotate_left(WORD_ROTATE);
        chunk.copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// ABI branch preimage: three uint256 words, each 24 zero bytes then the value big-endian.
pub fn abi_preimage(a: u64, b: u64, c: u64) -> [u8; 96] {
    let mut out = [0u8; 96];
    for (word, value) in out.chunks_exact_mut(32).zip([a, b, c]) {
        word[24..].copy_from_slice(&value.to_be_bytes());
    }
    out
}

/// MessagePack branch preimage: at most 28 bytes (`0x93` plus three 9-byte integers).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PackedPreimage {
    bytes: [u8; 28],
    len: usize,
}

impl PackedPreimage {
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    fn push(&mut self, data: &[u8]) {
        self.bytes[self.len..self.len + data.len()].copy_from_slice(data);
        self.len += data.len();
    }

    fn push_uint(&mut self, value: u64) {
        if value < 0x100 {
            if value < 0x80 {
                self.push(&[value as u8]);
            } else {
                self.push(&[0xcc, value as u8]);
            }
        } else if value < 0x1_0000 {
            self.push(&[0xcd]);
            self.push(&(value as u16).to_be_bytes());
        } else if value >> 32 == 0 {
            self.push(&[0xce]);
            self.push(&(value as u32).to_be_bytes());
        } else {
            self.push(&[0xcf]);
            self.push(&value.to_be_bytes());
        }
    }
}

/// Fixed array of three (marker `0x90 | 3`), then each value in its smallest unsigned form.
pub fn message_pack_preimage(a: u64, b: u64, c: u64) -> PackedPreimage {
    let mut out = PackedPreimage { bytes: [0; 28], len: 0 };
    out.push(&[0x90 | 3]);
    out.push_uint(a);
    out.push_uint(b);
    out.push_uint(c);
    out
}

/// Keccak-256 (rate 136, delimiter `0x01`) of a message that fits in one block.
/// The preimages of this flow are at most 96 bytes, so multi-block input is out of scope.
pub fn keccak256_short(message: &[u8]) -> [u8; 32] {
    assert!(message.len() < RATE, "single-block messages only");
    let mut block = [0u8; 200];
    block[..message.len()].copy_from_slice(message);
    block[message.len()] ^= KECCAK_DELIMITER;
    block[RATE - 1] ^= 0x80;
    let mut lanes = [0u64; 25];
    for (lane, bytes) in lanes.iter_mut().zip(block.chunks_exact(8)) {
        *lane = u64::from_le_bytes(bytes.try_into().expect("eight-byte lane"));
    }
    permute(&mut lanes);
    let mut out = [0u8; 32];
    for (bytes, lane) in out.chunks_exact_mut(8).zip(lanes) {
        bytes.copy_from_slice(&lane.to_le_bytes());
    }
    out
}

fn leading_zero_bytes(value: u64) -> usize {
    (value.leading_zeros() / 8) as usize
}

fn put_length_prefixed(digest: &mut [u8; 32], at: usize, value: u64, zeros: usize) -> usize {
    let kept = 8 - zeros;
    digest[at] = kept as u8;
    digest[at + 1..at + 1 + kept].copy_from_slice(&value.to_be_bytes()[zeros..]);
    at + 1 + kept
}

/// Final assembly: `len||a`, `len||b` (leading zero bytes dropped, zero has length 0)
/// from offset 10, then `len||c` only if `za + zb + 4 >= 9 - zc` (zN = leading zero
/// bytes of N), i.e. if the whole field fits before byte 32. Other bytes keep the base.
pub fn overlay_tail(digest: &mut [u8; 32], a: u64, b: u64, c: u64) {
    let (za, zb, zc) = (leading_zero_bytes(a), leading_zero_bytes(b), leading_zero_bytes(c));
    let after_a = put_length_prefixed(digest, OVERLAY_START, a, za);
    let after_b = put_length_prefixed(digest, after_a, b, zb);
    if za + zb + 4 >= 9 - zc {
        put_length_prefixed(digest, after_b, c, zc);
    }
}

/// The 32 base bytes before the overlay.
pub fn base_bytes(mode: u8, a: u64, b: u64, c: u64) -> [u8; 32] {
    match select_source(mode, a) {
        Source::Arithmetic => arithmetic_words(a, b, c),
        Source::Abi => keccak256_short(&abi_preimage(a, b, c)),
        Source::MessagePack => keccak256_short(message_pack_preimage(a, b, c).as_slice()),
    }
}

/// Whole `0x421dc00`: `base_bytes`, then `overlay_tail`.
pub fn event_context(mode: u8, a: u64, b: u64, c: u64) -> [u8; 32] {
    let mut digest = base_bytes(mode, a, b, c);
    overlay_tail(&mut digest, a, b, c);
    digest
}

/// The buffer the spot-deploy charge body `0x2c57090` hands to its event helper
/// (`0x2c574be`/`0x2c57776`): `event_context(mode, word_28, word_08, 0)` when the
/// 32-bit tag at the start of the state is 1, otherwise 32 zero bytes.
/// `word_28`/`word_08` are the state qwords at `+0x28`/`+0x08`, `mode` the byte at
/// `+0xb9a`; this call site always passes 0 as the third value. Names are not known.
/// The sibling charge bodies `0x55cbcc0` (mode byte at `+0x170a`, call `0x55cc0de`) and
/// `0x55cc610` (`+0xb9a`, call `0x55cca2e`) have the same call-site pattern.
pub fn spot_deploy_charge_context(state_tag: u32, mode: u8, word_28: u64, word_08: u64) -> [u8; 32] {
    if state_tag == 1 {
        event_context(mode, word_28, word_08, 0)
    } else {
        [0; 32]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex<const N: usize>(text: &str) -> [u8; N] {
        core::array::from_fn(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap())
    }

    #[test]
    fn keccak_short_matches_published_vectors() {
        assert_eq!(
            keccak256_short(b""),
            hex::<32>("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
        );
        assert_eq!(
            keccak256_short(b"abc"),
            hex::<32>("4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45")
        );
    }

    #[test]
    fn message_pack_width_boundaries() {
        let cases: [(u64, &[u8]); 10] = [
            (0, &[0x00]),
            (0x7f, &[0x7f]),
            (0x80, &[0xcc, 0x80]),
            (0xff, &[0xcc, 0xff]),
            (0x100, &[0xcd, 0x01, 0x00]),
            (0xffff, &[0xcd, 0xff, 0xff]),
            (0x1_0000, &[0xce, 0x00, 0x01, 0x00, 0x00]),
            (0xffff_ffff, &[0xce, 0xff, 0xff, 0xff, 0xff]),
            (1 << 32, &[0xcf, 0, 0, 0, 1, 0, 0, 0, 0]),
            (u64::MAX, &[0xcf, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
        ];
        for (value, bytes) in cases {
            let packed = message_pack_preimage(value, 0, 0);
            assert_eq!(packed.as_slice()[0], 0x93);
            assert_eq!(&packed.as_slice()[1..1 + bytes.len()], bytes);
            assert_eq!(packed.as_slice().len(), 1 + bytes.len() + 2);
        }
        assert_eq!(message_pack_preimage(u64::MAX, u64::MAX, u64::MAX).as_slice().len(), 28);
    }

    #[test]
    fn abi_words_are_big_endian_in_the_last_eight_bytes() {
        let bytes = abi_preimage(1, 0x0102_0304_0506_0708, u64::MAX);
        assert_eq!(&bytes[..24], &[0; 24]);
        assert_eq!(bytes[31], 1);
        assert_eq!(&bytes[56..64], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(&bytes[88..], &[0xff; 8]);
        assert_eq!(&bytes[64..88], &[0; 24]);
    }

    #[test]
    fn branch_choice_at_every_threshold() {
        use Source::*;
        for mode in [0, 1] {
            assert_eq!(select_source(mode, 0), Arithmetic);
            assert_eq!(select_source(mode, 0x0df5_9bc0), Arithmetic);
        }
        let mode2 = [(0x0df5_9bbf, Abi), (0x0df5_9bc0, MessagePack), (0x1906_7a34, MessagePack), (0x1906_7a35, Arithmetic)];
        for (a, expected) in mode2 {
            assert_eq!(select_source(2, a), expected, "mode 2, a = {a:#x}");
        }
        for mode in [3u8, 4, 255] {
            let later = [(0x0d37_7be0, Abi), (0x0d37_7be1, MessagePack), (0x2a16_6de8, MessagePack), (0x2a16_6de9, Arithmetic)];
            for (a, expected) in later {
                assert_eq!(select_source(mode, a), expected, "mode {mode}, a = {a:#x}");
            }
        }
    }

    #[test]
    fn overlay_keeps_unwritten_bytes_and_drops_leading_zeros() {
        let mut digest = [0xaa; 32];
        overlay_tail(&mut digest, 0, 0x0102, 0);
        let mut expected = [0xaa; 32];
        expected[10..15].copy_from_slice(&[0, 2, 1, 2, 0]);
        assert_eq!(digest, expected);
    }

    #[test]
    fn overlay_skips_a_third_field_that_does_not_fit() {
        // a and b take 9 bytes each, leaving 4 bytes: c fits up to 3 bytes (1 + 3), not 4.
        let mut fits = [0u8; 32];
        overlay_tail(&mut fits, u64::MAX, u64::MAX, 0x00ff_ffff);
        assert_eq!(&fits[28..], &[3, 0xff, 0xff, 0xff]);
        let mut skipped = [0x55u8; 32];
        overlay_tail(&mut skipped, u64::MAX, u64::MAX, 0x0100_0000);
        assert_eq!(&skipped[28..], &[0x55; 4]);
    }

    #[test]
    fn spot_deploy_context_is_zero_unless_the_tag_is_one() {
        for tag in [0u32, 2, 3, 0x100, u32::MAX] {
            assert_eq!(spot_deploy_charge_context(tag, 3, 0x1000_0000, 77), [0; 32]);
        }
        assert_eq!(spot_deploy_charge_context(1, 3, 0x1000_0000, 77), event_context(3, 0x1000_0000, 77, 0));
    }
}
