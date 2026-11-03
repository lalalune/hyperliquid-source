//! Node115 scalar Decimal96 normalization, independently authored from static evidence.
//! The four-word projection is a research value type, not a recovered native ABI.
#![no_std]

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Normalized {
    pub coefficient: u128,
    pub flags: u32,
}

impl Normalized {
    /// Values stored at native stack offsets +b8, +bc, +c0, +c4.
    pub fn observed_words(self) -> [u32; 4] {
        [self.flags, (self.coefficient >> 64) as u32,
         self.coefficient as u32, (self.coefficient >> 32) as u32]
    }
}

/// Normalize a 96-bit coefficient and raw flags at the selected arithmetic cut.
///
/// The input limbs define the entire numeric domain without a guessed native type.
/// Raw flags are not a claim about the opaque upstream parser's accepted inputs.
/// Zero clears all flags. An initially zero scale preserves all raw flags.
/// Otherwise remove at most `scale` decimal zeros and retain only sign and scale.
pub fn normalize_parts(lo: u32, mid: u32, hi: u32, flags: u32) -> Normalized {
    let mut coefficient = (u128::from(hi) << 64) | (u128::from(mid) << 32) | u128::from(lo);
    if coefficient == 0 {
        return Normalized { coefficient: 0, flags: 0 };
    }
    let mut scale = (flags >> 16) & 255;
    if scale == 0 {
        return Normalized { coefficient, flags };
    }
    while scale > 0 && coefficient % 10 == 0 {
        coefficient /= 10;
        scale -= 1;
    }
    Normalized { coefficient, flags: (flags & 0x8000_0000) | (scale << 16) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_and_initial_zero_scale_have_distinct_flag_rules() {
        assert_eq!(normalize_parts(0, 0, 0, u32::MAX).observed_words(), [0; 4]);
        assert_eq!(normalize_parts(10, 0, 0, 0xc000_0001).observed_words(),
                   [0xc000_0001, 0, 10, 0]);
        assert_eq!(normalize_parts(11, 0, 0, 0xc002_0001).observed_words(),
                   [0x8002_0000, 0, 11, 0]);
    }

    #[test]
    fn scale_limits_trimming_and_high_limb_is_not_truncated() {
        assert_eq!(normalize_parts(1000, 0, 0, 0x8002_0000).observed_words(),
                   [0x8000_0000, 0, 10, 0]);
        let n = (1u128 << 64) * 10;
        assert_eq!(normalize_parts(n as u32, (n >> 32) as u32, (n >> 64) as u32, 1 << 16),
                   Normalized { coefficient: 1u128 << 64, flags: 0 });
    }

    #[test]
    fn frozen_target_grounded_cases() {
        let mut count = 0;
        for line in include_str!("target-vectors.tsv").lines() {
            let mut words = [0u32; 8];
            let mut fields = line.split('\t');
            for word in &mut words {
                *word = fields.next().expect("eight fields").parse().expect("u32");
            }
            assert!(fields.next().is_none());
            assert_eq!(normalize_parts(words[0], words[1], words[2], words[3]).observed_words(),
                       [words[4], words[5], words[6], words[7]], "case {}", count);
            count += 1;
        }
        assert_eq!(count, 9856);
    }
}
