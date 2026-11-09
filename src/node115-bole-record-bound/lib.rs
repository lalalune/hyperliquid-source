//! Selected BOLE work-record construction after the credited scale-helper call.
//! This does not implement scale lookup, asynchronous polling or an operation.
#![no_std]
#![forbid(unsafe_code)]
use core::num::NonZeroU64;
pub const PRODUCT_CAP: u64 = 1_000_000_000_000_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Bound {
    pub factor: NonZeroU64,
    pub capped: u64,
    pub product: u64,
}

/// 0x2c808ab/af increments only zero, before passing R8 to the constructor.
pub fn caller_factor(converted: u64) -> NonZeroU64 {
    NonZeroU64::new(converted).unwrap_or(NonZeroU64::MIN)
}

/// Universally quantified over the u64 result of credited helper 0x434f580.
/// No guessed implementation of that helper is substituted. The product is
/// bounded by 10^18, so its later native >2^63-2/overflow refusal cannot fire.
pub fn bound(scale_result: u64, factor: NonZeroU64) -> Bound {
    let capped = scale_result.min(PRODUCT_CAP / factor.get());
    Bound {
        factor,
        capped,
        product: capped * factor.get(),
    }
}

/// Successful record's explicitly written bytes through offset 0x284. Supplied
/// initialized prefix bytes are opaque. Native padding after this is unspecified.
pub fn build_record(
    prefix: [u8; 0x250],
    index: u64,
    stamp: [u8; 12],
    flag: u8,
    value: Bound,
) -> [u8; 0x285] {
    let mut out = [0; 0x285];
    out[..0x250].copy_from_slice(&prefix);
    for (offset, word) in [
        (0x250, value.factor.get()),
        (0x258, index),
        (0x260, value.capped),
        (0x268, value.product),
        (0x270, 0),
    ] {
        out[offset..offset + 8].copy_from_slice(&word.to_le_bytes());
    }
    out[0x278..0x284].copy_from_slice(&stamp);
    out[0x284] = flag;
    out
}

/// The selected caller copies the constructed fields, then replaces +0x270 with
/// its saved lookup word. This returns only initialized fields through +0x284;
/// three additional bytes copied at the native tail remain unspecified padding.
pub fn selected_record(
    prefix: [u8; 0x250],
    index: u64,
    stamp: [u8; 12],
    saved_lookup_word: u64,
    value: Bound,
) -> [u8; 0x285] {
    let mut out = build_record(prefix, index, stamp, 1, value);
    out[0x270..0x278].copy_from_slice(&saved_lookup_word.to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn caller_excludes_zero_divisor_without_wrapping_max() {
        assert_eq!(caller_factor(0).get(), 1);
        assert_eq!(caller_factor(1).get(), 1);
        assert_eq!(caller_factor(u64::MAX).get(), u64::MAX);
    }
    #[test]
    fn cap_rounding_and_large_factors() {
        let v = bound(u64::MAX, caller_factor(3));
        assert_eq!(v.capped, 333_333_333_333_333_333);
        assert_eq!(v.product, PRODUCT_CAP - 1);
        assert_eq!(bound(5, caller_factor(3)).product, 15);
        assert_eq!(bound(u64::MAX, caller_factor(PRODUCT_CAP + 1)).product, 0);
    }
    #[test]
    fn wide_oracle_and_refusal_unreachability() {
        let mut state = 0x123456789abcdef0u64;
        let special = [
            0,
            1,
            2,
            3,
            PRODUCT_CAP - 1,
            PRODUCT_CAP,
            PRODUCT_CAP + 1,
            (1u64 << 63) - 2,
            u64::MAX,
        ];
        for n in 0..4096 {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let scaled = if n < special.len() { special[n] } else { state };
            state = state.rotate_left(23) ^ 0x9e3779b97f4a7c15;
            let factor = caller_factor(if n < special.len() {
                special[special.len() - 1 - n]
            } else {
                state
            });
            let got = bound(scaled, factor);
            let product = u128::from(scaled) * u128::from(factor.get());
            let expected = if product <= u128::from(PRODUCT_CAP) {
                scaled
            } else {
                (u128::from(PRODUCT_CAP) / u128::from(factor.get())) as u64
            };
            assert_eq!(got.capped, expected);
            assert_eq!(
                u128::from(got.product),
                u128::from(expected) * u128::from(factor.get())
            );
            assert!(got.product <= PRODUCT_CAP);
            assert!(got.product <= (1u64 << 63) - 2);
        }
    }
    #[test]
    fn caller_replaces_constructor_zero_and_preserves_other_fields() {
        let bound = bound(23, caller_factor(7));
        let original = build_record([0x61; 0x250], 3, [0x42; 12], 1, bound);
        let final_record = selected_record([0x61; 0x250], 3, [0x42; 12], 89, bound);
        assert_eq!(&final_record[..0x270], &original[..0x270]);
        assert_eq!(&final_record[0x270..0x278], &89u64.to_le_bytes());
        assert_eq!(&final_record[0x278..], &original[0x278..]);
    }
    #[test]
    fn exact_tail_fields_and_opaque_prefix_preservation() {
        let prefix = core::array::from_fn(|i| (i % 251) as u8);
        let stamp = core::array::from_fn(|i| (0xa0 + i) as u8);
        let result = build_record(prefix, 7, stamp, 1, bound(9, caller_factor(4)));
        assert_eq!(&result[..0x250], &prefix);
        for (offset, value) in [
            (0x250, 4u64),
            (0x258, 7),
            (0x260, 9),
            (0x268, 36),
            (0x270, 0),
        ] {
            assert_eq!(&result[offset..offset + 8], &value.to_le_bytes());
        }
        assert_eq!(&result[0x278..0x284], &stamp);
        assert_eq!(result[0x284], 1);
    }
}
