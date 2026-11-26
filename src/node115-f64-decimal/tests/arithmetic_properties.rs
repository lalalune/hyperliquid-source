use node115_f64_decimal::{Decimal96, from_binary_parts, from_f64_bits};
#[test]
fn exactly_representable_powers_use_the_mathematical_integer_oracle() {
    for exponent in -20..=95 {
        let (coefficient, scale) = if exponent < 0 {
            (5_u128.pow((-exponent) as u32), (-exponent) as u32)
        } else {
            (1_u128 << exponent, 0)
        };
        for negative in [false, true] {
            let bits = 2_f64.powi(exponent).to_bits() | (u64::from(negative) << 63);
            assert_eq!(
                from_f64_bits(bits),
                Some(Decimal96 {
                    coefficient,
                    scale,
                    negative
                })
            );
        }
    }
}
#[test]
fn bit_patterns_preserve_sign_and_output_domain() {
    let mut state = 0x18d5_ae09_b4f2_7c63_u64;
    for _ in 0..4096 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let positive = state & 0x7fff_ffff_ffff_ffff;
        let a = from_f64_bits(positive);
        let b = from_f64_bits(positive | 0x8000_0000_0000_0000);
        assert_eq!(a.is_some(), b.is_some());
        if let (Some(a), Some(b)) = (a, b) {
            assert_eq!((a.coefficient, a.scale), (b.coefficient, b.scale));
            assert!(!a.negative && b.negative);
            assert!(a.coefficient < (1_u128 << 96));
            assert!(a.scale <= 28);
            if a.scale > 0 {
                assert!(a.coefficient < (1_u128 << 52));
                assert_ne!(a.coefficient % 10, 0);
            }
        }
    }
    assert_eq!(from_binary_parts(1_u128 << 96, 0, false), None);
    assert_eq!(from_binary_parts(1, -1075, false), None);
    assert_eq!(from_binary_parts(1, 1024, false), None);
}
