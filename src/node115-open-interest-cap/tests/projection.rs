use node115_open_interest_cap::{project, Input, NegativeAddend, Outcome};

fn input(sum_left: i64, sum_right: i64, multiplier: i64) -> Input {
    Input {
        sum_left,
        sum_right,
        multiplier,
        key: 7,
        selector: 0xa5,
        observed_cap_word: i64::MIN,
    }
}

fn format_bits(outcome: Outcome) -> (u32, u8, u64) {
    match outcome {
        Outcome::Format {
            mapped_key,
            selector,
            open_interest,
        } => (mapped_key, selector, open_interest.to_bits()),
        other => panic!("expected format arguments, got {other:?}"),
    }
}

#[test]
fn negative_stack_addend_is_a_host_refusal_before_any_projection() {
    for right in [-1, i64::MIN] {
        for left in [0, i64::MIN, i64::MAX] {
            assert_eq!(project(input(left, right, -1)), Err(NegativeAddend));
        }
    }
}

#[test]
fn both_signed_thresholds_are_strict_on_the_sentinel_side() {
    // Manual CMP/SETL and branch observations at 0x447c69a..0x447c6e3.
    let cases = [
        (184_467_440_737_095_516, false, false),
        (184_467_440_737_095_517, true, false),
        (184_467_440_737_095_518, true, false),
        (1_844_674_407_370_955_161, true, false),
        (1_844_674_407_370_955_162, true, true),
        (1_844_674_407_370_955_163, true, true),
    ];
    for (product, cap_request, formatting) in cases {
        let result = project(input(product, 0, 1)).unwrap();
        assert!(!result.sum_overflow_request);
        assert_eq!(result.cap_request, cap_request, "product={product}");
        assert_eq!(matches!(result.outcome, Outcome::Format { .. }), formatting);
    }
}

#[test]
fn context_observation_controls_only_the_lower_diagnostic() {
    for observed in [i64::MIN + 1, -1, 0, i64::MAX] {
        let mut value = input(1_844_674_407_370_955_162, 0, 1);
        value.observed_cap_word = observed;
        let result = project(value).unwrap();
        assert!(!result.cap_request);
        assert!(matches!(result.outcome, Outcome::Format { .. }));
    }
    // The lower threshold can diagnose and still take the sentinel route.
    let result = project(input(184_467_440_737_095_517, 0, 1)).unwrap();
    assert!(result.cap_request);
    assert_eq!(result.outcome, Outcome::SentinelOnly);
}

#[test]
fn addition_overflow_is_reported_before_the_later_decision() {
    let zero = project(input(i64::MAX, 1, 0)).unwrap();
    assert!(zero.sum_overflow_request);
    assert!(!zero.cap_request);
    assert_eq!(zero.outcome, Outcome::SentinelOnly);

    let one = project(input(i64::MAX, 1, 1)).unwrap();
    assert!(one.sum_overflow_request && one.cap_request);
    assert_eq!(format_bits(one.outcome).2, 0x42a0_c6f7_a0b5_ed8d);

    let two = project(input(i64::MAX, 1, 2)).unwrap();
    assert!(two.sum_overflow_request && two.cap_request);
    assert_eq!(format_bits(two.outcome).2, 0);

    let no_overflow = project(input(i64::MIN, i64::MAX, i64::MAX)).unwrap();
    assert!(!no_overflow.sum_overflow_request && !no_overflow.cap_request);
    assert_eq!(no_overflow.outcome, Outcome::SentinelOnly);
}

#[test]
fn signed_products_and_both_multiplication_overflow_directions() {
    for (left, multiplier) in [(i64::MIN, 1), (-3, 7), (0, i64::MAX)] {
        let result = project(input(left, 0, multiplier)).unwrap();
        assert!(!result.cap_request);
        assert_eq!(result.outcome, Outcome::SentinelOnly);
    }
    for (left, multiplier) in [(i64::MIN, 2), (i64::MAX, 2)] {
        let result = project(input(left, 0, multiplier)).unwrap();
        assert!(result.cap_request);
        assert_eq!(format_bits(result.outcome).2, 0); // positive zero
    }
    // Fitting negative product at the exact limit; one more factor overflows.
    assert_eq!(
        project(input(-(1_i64 << 62), 0, 2)).unwrap().outcome,
        Outcome::SentinelOnly
    );
    assert_eq!(
        format_bits(project(input(-(1_i64 << 62), 0, 3)).unwrap().outcome).2,
        0
    );
}

#[test]
fn a_negative_multiplier_is_invalid_even_when_a_product_would_fit() {
    for multiplier in [-1, i64::MIN] {
        for left in [0, 1, -1] {
            let result = project(input(left, 0, multiplier)).unwrap();
            assert!(result.cap_request);
            assert_eq!(format_bits(result.outcome).2, 0);
        }
    }
}

#[test]
fn mapping_uses_unsigned_full_key_boundaries() {
    for (key, expected) in [
        (0, 0),
        (9_999, 9_999),
        (10_000, 110_000),
        (99_899_999, 99_999_999),
        (99_900_000, u32::MAX),
        (u32::MAX as u64, u32::MAX),
        (u64::MAX, u32::MAX),
    ] {
        let mut value = input(0, 0, -1);
        value.key = key;
        assert_eq!(format_bits(project(value).unwrap().outcome).0, expected);
    }
}

#[test]
fn raw_selector_is_preserved_for_all_256_values() {
    for selector in u8::MIN..=u8::MAX {
        let mut value = input(0, 0, -1);
        value.selector = selector;
        assert_eq!(format_bits(project(value).unwrap().outcome).1, selector);
    }
}

#[test]
fn conversion_then_division_matches_independent_rational_goldens() {
    // Exact rational nearest-even derivation is retained in the packet.
    // The first and the tie rows reject replacing two rounds with one round
    // of the exact rational product/1_000_000.
    let cases = [
        (1_844_674_407_370_955_162, 0x427a_d7f2_9abc_af49),
        (1_844_674_407_370_955_163, 0x427a_d7f2_9abc_af49),
        (1_844_674_407_370_955_289, 0x427a_d7f2_9abc_af49),
        (1_844_674_407_370_955_290, 0x427a_d7f2_9abc_af49),
        (2_305_843_009_213_693_951, 0x4280_c6f7_a0b5_ed8d),
        (2_305_843_009_213_693_952, 0x4280_c6f7_a0b5_ed8d),
        (2_305_843_009_213_694_208, 0x4280_c6f7_a0b5_ed8d),
        (2_305_843_009_213_694_720, 0x4280_c6f7_a0b5_ed8f),
        (4_611_686_018_427_387_903, 0x4290_c6f7_a0b5_ed8d),
        (4_611_686_018_427_388_416, 0x4290_c6f7_a0b5_ed8d),
        (9_223_372_036_854_775_807, 0x42a0_c6f7_a0b5_ed8d),
    ];
    for (product, bits) in cases {
        let result = project(input(product, 0, 1)).unwrap();
        assert_eq!(format_bits(result.outcome).2, bits, "product={product}");
    }
}
