//! Value-level model of the node #115 scheduled-observer factor path.
//!
//! Target identity: SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
//! The 79 entries and post-multiply normalizer are pinned by
//! `research/work-items/RE-015-scheduled-observer-115`.

/// The captured 79-entry table indexed by the established #115 config-name tag.
/// `None` means outside the evidenced 0..79 research domain; the native selector
/// itself has no local bounds check, so this is not a model of native rejection.
pub fn factor_bits(index: usize) -> Option<u64> {
    FACTOR_BITS.get(index).copied()
}

/// Apply the observer's factor and then the selected constructor normalizer.
///
/// The product uses Rust's binary64 multiplication. This value model does not
/// reproduce the native ABI, floating-point exception state, or all runtime FP
/// environment settings.
pub fn observer_value(initializer_bits: u64, index: usize) -> Option<u64> {
    let factor = f64::from_bits(factor_bits(index)?);
    let product = f64::from_bits(initializer_bits) * factor;
    Some(normalize_product(product.to_bits()))
}

/// Model the selected bit-level normalizer after the binary64 multiplication.
/// Positive finite nonzero values and both signed zeros pass unchanged; negative
/// nonzero values and non-finite values become positive zero.
pub fn normalize_product(bits: u64) -> u64 {
    const SIGN: u64 = 1 << 63;
    const MAGNITUDE: u64 = !SIGN;
    const EXPONENT: u64 = 0x7ff0_0000_0000_0000;
    let magnitude = bits & MAGNITUDE;
    if magnitude == 0 || (bits & SIGN == 0 && magnitude & EXPONENT != EXPONENT) {
        bits
    } else {
        0
    }
}

const FACTOR_BITS: [u64; 79] = [
    0x4014000000000000u64,
    0x3ff0000000000000u64,
    0x3ff0000000000000u64,
    0x4014000000000000u64,
    0x4014000000000000u64,
    0x4014000000000000u64,
    0x4014000000000000u64,
    0x4014000000000000u64,
    0x4014000000000000u64,
    0x3ff0000000000000u64,
    0x3ff0000000000000u64,
    0x3ff0000000000000u64,
    0x3ff0000000000000u64,
    0x3ff0000000000000u64,
    0x4014000000000000u64,
    0x3ff0000000000000u64,
    0x3ff0000000000000u64,
    0x4014000000000000u64,
    0x3ff0000000000000u64,
    0x4014000000000000u64,
    0x3ff0000000000000u64,
    0x4014000000000000u64,
    0x3ff0000000000000u64,
    0x4014000000000000u64,
    0x4014000000000000u64,
    0x3ff0000000000000u64,
    0x3ff0000000000000u64,
    0x4014000000000000u64,
    0x4014000000000000u64,
    0x4014000000000000u64,
    0x4014000000000000u64,
    0x4014000000000000u64,
    0x4014000000000000u64,
    0x4014000000000000u64,
    0x4014000000000000u64,
    0x3ff0000000000000u64,
    0x3ff0000000000000u64,
    0x3ff0000000000000u64,
    0x3ff0000000000000u64,
    0x4014000000000000u64,
    0x4014000000000000u64,
    0x4014000000000000u64,
    0x4014000000000000u64,
    0x4014000000000000u64,
    0x4014000000000000u64,
    0x4014000000000000u64,
    0x4014000000000000u64,
    0x4014000000000000u64,
    0x4014000000000000u64,
    0x4014000000000000u64,
    0x4014000000000000u64,
    0x4014000000000000u64,
    0x4014000000000000u64,
    0x4014000000000000u64,
    0x4014000000000000u64,
    0x4014000000000000u64,
    0x4014000000000000u64,
    0x4014000000000000u64,
    0x4014000000000000u64,
    0x4014000000000000u64,
    0x4014000000000000u64,
    0x4014000000000000u64,
    0x4014000000000000u64,
    0x4014000000000000u64,
    0x4014000000000000u64,
    0x4014000000000000u64,
    0x4014000000000000u64,
    0x4014000000000000u64,
    0x4014000000000000u64,
    0x4014000000000000u64,
    0x4014000000000000u64,
    0x4014000000000000u64,
    0x4014000000000000u64,
    0x4014000000000000u64,
    0x4014000000000000u64,
    0x4014000000000000u64,
    0x4014000000000000u64,
    0x4014000000000000u64,
    0x4014000000000000u64,
];
#[cfg(test)]
mod tests {
    use super::{factor_bits, normalize_product, observer_value};

    #[test]
    fn factor_table_matches_all_packet_runs() {
        let runs = include_str!(
            "../../../research/work-items/RE-015-scheduled-observer-115/factor-runs.tsv"
        );
        let mut reconstructed = [0u64; 79];
        let mut covered = [false; 79];
        for row in runs.lines().skip(1) {
            let fields: Vec<_> = row.split('\t').collect();
            let start: usize = fields[0].parse().unwrap();
            let end: usize = fields[1].parse().unwrap();
            let count: usize = fields[3].parse().unwrap();
            let bits = u64::from_str_radix(fields[4].trim_start_matches("0x"), 16).unwrap();
            assert_eq!(end - start + 1, count);
            for index in start..=end {
                assert!(!covered[index], "duplicate table index {index}");
                reconstructed[index] = bits;
                covered[index] = true;
            }
        }
        assert!(covered.into_iter().all(|entry| entry));
        for (index, expected) in reconstructed.into_iter().enumerate() {
            assert_eq!(factor_bits(index), Some(expected), "index={index}");
        }
        assert_eq!(factor_bits(79), None);
    }

    #[test]
    fn initializer_examples_match_selected_tags() {
        let initializer = 0x3fb9_9999_9999_999a;
        assert_eq!(observer_value(initializer, 33), Some(0x3fe0_0000_0000_0000));
        assert_eq!(observer_value(initializer, 35), Some(initializer));
    }

    #[test]
    fn product_normalizer_matches_packet_cases() {
        let cases = include_str!(
            "../../../research/work-items/RE-015-scheduled-observer-115/product-model.tsv"
        );
        let mut count = 0;
        for row in cases.lines().skip(1) {
            let fields: Vec<_> = row.split('\t').collect();
            let input = u64::from_str_radix(fields[1], 16).unwrap();
            let expected = u64::from_str_radix(fields[2], 16).unwrap();
            assert_eq!(normalize_product(input), expected, "case={}", fields[0]);
            count += 1;
        }
        assert_eq!(count, 13);
    }

    #[test]
    fn normalizer_covers_sign_exponent_and_fraction_boundaries() {
        let fractions = [0, 1, 1 << 51, (1 << 52) - 1];
        let mut checked = 0;
        for sign in 0..=1 {
            for exponent in 0..=0x7ff {
                for fraction in fractions {
                    let bits = (sign << 63) | (exponent << 52) | fraction;
                    let magnitude = bits & !(1 << 63);
                    let expected = if exponent == 0x7ff || (sign == 1 && magnitude != 0) {
                        0
                    } else {
                        bits
                    };
                    assert_eq!(normalize_product(bits), expected);
                    checked += 1;
                }
            }
        }
        assert_eq!(checked, 16_384);
    }
}
