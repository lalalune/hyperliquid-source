//! Predicate recovered from node #94 at 0x27c1d29..0x27c2138.
//!
//! This is the bloom prefilter only: passing it does not establish a log match.
//! The slices are a new safe API, not the original Rust layout or ABI. See the
//! RE-001-evm-bloom-prefilter-94 packet for bytes, control flow and limitations.
#![no_std]
#![forbid(unsafe_code)]

pub type Bloom = [u8; 256];

fn contains(block: &Bloom, mask: &Bloom) -> bool {
    block.iter().zip(mask).all(|(b, m)| b & m == *m)
}

/// Each nonempty mask list requires at least one contained mask. All groups
/// must pass. Empty lists impose no restriction; an all-zero mask always fits.
///
/// Mask construction, exact address/topic matching and RPC admission are outside
/// this function. In particular, `groups` are positive conditions, not exclusions.
pub fn may_match(block: &Bloom, flat: &[Bloom], groups: &[&[Bloom]]) -> bool {
    (flat.is_empty() || flat.iter().any(|mask| contains(block, mask)))
        && groups
            .iter()
            .all(|group| group.is_empty() || group.iter().any(|mask| contains(block, mask)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn low_bits(bits: u8) -> Bloom {
        let mut value = [0; 256];
        value[0] = bits;
        value
    }

    #[test]
    fn empty_lists_bypass_their_loops() {
        // 0x27c1d2f, 0x27c1f21 and 0x27c1f59.
        assert!(may_match(&[0; 256], &[], &[]));
        assert!(may_match(&[0; 256], &[], &[&[], &[]]));
    }

    #[test]
    fn masks_require_every_bit_and_cover_all_256_bytes() {
        // All 16 SIMD lanes feed bcmp(..., 0x100), in both loops.
        for bit in 0..2048 {
            let mut mask = [0; 256];
            mask[bit / 8] = 1 << (bit % 8);
            assert!(may_match(&mask, &[mask], &[&[mask]]));
            assert!(!may_match(&[0; 256], &[mask], &[]));
            assert!(!may_match(&[0; 256], &[], &[&[mask]]));
            let mut missing = [255; 256];
            missing[bit / 8] &= !mask[bit / 8];
            assert!(!may_match(&missing, &[[255; 256]], &[]));
            assert!(!may_match(&missing, &[], &[&[[255; 256]]]));
        }
    }

    #[test]
    fn alternatives_are_or_and_groups_are_and() {
        let one = low_bits(1);
        let two = low_bits(2);
        assert!(may_match(&one, &[two, one], &[&[two, one]]));
        assert!(!may_match(&one, &[two], &[&[one]]));
        assert!(!may_match(&one, &[one], &[&[one], &[two]]));
        assert!(may_match(&low_bits(3), &[one], &[&[one], &[two]]));
    }

    #[test]
    fn a_matched_group_is_not_an_exclusion() {
        // Equality at 0x27c212b falls through to the *next* group, not rejection.
        let one = low_bits(1);
        assert!(may_match(&one, &[], &[&[one]]));
        assert!(!may_match(&[0; 256], &[], &[&[one]]));
    }

    #[test]
    fn zero_mask_always_matches() {
        assert!(may_match(&[0; 256], &[[0; 256]], &[&[[0; 256]]]));
        assert!(may_match(&[255; 256], &[[0; 256]], &[&[[0; 256]]]));
    }
}
