use visor_duration_value::convert_bits;

fn pair(bits: u64) -> (u64, u32) {
    let value = convert_bits(bits);
    (value.seconds(), value.nanoseconds())
}

#[test]
fn zeros_negative_values_and_every_nonfinite_class_are_zero() {
    for bits in [
        0,
        0x8000_0000_0000_0000,
        0xbff0_0000_0000_0000,
        0xffef_ffff_ffff_ffff,
        0x8000_0000_0000_0001,
        0x7ff0_0000_0000_0000,
        0xfff0_0000_0000_0000,
        0x7ff0_0000_0000_0001,
        0x7ff8_0000_0000_0000,
        0xffff_ffff_ffff_ffff,
    ] {
        assert_eq!(pair(bits), (0, 0));
    }
}

#[test]
fn tiny_inputs_cross_the_first_nanosecond() {
    assert_eq!(pair(1), (0, 0));
    assert_eq!(pair(0x000f_ffff_ffff_ffff), (0, 0));
    assert_eq!(pair(0x3dff_ffff_ffff_ffff), (0, 0));
    // 2^-31 * 10^9 < 1/2; 2^-30 * 10^9 lies between 1/2 and 1.
    assert_eq!(pair(0x3e00_0000_0000_0000), (0, 0));
    assert_eq!(pair(0x3e10_0000_0000_0000), (0, 1));
}

#[test]
fn integral_seconds_are_exact_across_fraction_regimes() {
    for (bits, seconds) in [
        (0x3ff0_0000_0000_0000, 1),
        (0x4014_0000_0000_0000, 5),
        (0x404e_0000_0000_0000, 60),
        (0x4330_0000_0000_0001, 4_503_599_627_370_497),
    ] {
        assert_eq!(pair(bits), (seconds, 0));
    }
}

#[test]
fn exact_half_nanoseconds_use_even_parity() {
    // 2^-10 * 10^9 = 976562.5; three times that has odd lower integer.
    assert_eq!(pair(0x3f50_0000_0000_0000), (0, 976_562));
    assert_eq!(pair(0x3f68_0000_0000_0000), (0, 2_929_688));
    // Adding one second adds an even integer number of nanoseconds.
    assert_eq!(pair(0x3ff0_0400_0000_0000), (1, 976_562));
    assert_eq!(pair(0x3ff0_0c00_0000_0000), (1, 2_929_688));
}

#[test]
fn rounded_fraction_carries_into_the_second() {
    assert_eq!(pair(0x3fef_ffff_ffff_ffff), (1, 0));
    assert_eq!(pair(0x3fff_ffff_ffff_ffff), (2, 0));
}

#[test]
fn two_to_64_is_a_deliberate_discontinuity() {
    assert_eq!(pair(0x43ef_ffff_ffff_ffff), (18_446_744_073_709_549_568, 0));
    assert_eq!(
        pair(0x43f0_0000_0000_0000),
        (18_446_744_073_709, 551_615_000)
    );
    assert_eq!(
        pair(0x4400_0000_0000_0000),
        (18_446_744_073_709, 551_615_000)
    );
}

#[test]
fn scaled_overflow_boundary_is_adjacent_and_exact() {
    assert_eq!(
        pair(0x7eb0_c6f7_a0b5_ed8c),
        (18_446_744_073_709, 551_615_000)
    );
    assert_eq!(pair(0x7eb0_c6f7_a0b5_ed8d), (0, 0));
    assert_eq!(pair(0x7fef_ffff_ffff_ffff), (0, 0));
}

#[test]
fn every_exponent_and_sign_sample_has_a_canonical_remainder() {
    for exponent in 0..2048_u64 {
        for fraction in [0, 1, 0x0008_0000_0000_0000, 0x000f_ffff_ffff_ffff] {
            for sign in [0, 1_u64 << 63] {
                assert!(
                    convert_bits(sign | (exponent << 52) | fraction).nanoseconds() < 1_000_000_000
                );
            }
        }
    }
}
