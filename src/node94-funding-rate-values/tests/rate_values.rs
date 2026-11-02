use node94_funding_rate_values::{funding_rate_bits as rate, insertion_bits};

#[test]
fn absence_is_distinct_from_every_active_zero() {
    assert_eq!(rate(None, None, None, 0), None);
    assert_eq!(rate(Some(&[]), None, None, 0), None);
    assert_eq!(rate(Some(&[0]), Some(0), None, 0), Some(0));
    assert_eq!(insertion_bits(None), 0);
    assert_eq!(
        insertion_bits(Some(0x8000_0000_0000_0000)),
        0x8000_0000_0000_0000
    );
    assert_eq!(
        insertion_bits(Some(0xfff0_0000_0000_0123)),
        0xfff0_0000_0000_0123
    );
}

#[test]
fn clamp_zero_sign_changes_the_active_result() {
    let sample = [0x8000_0000_0000_0000];
    let interest = Some(0xbf1a_36e2_eb1c_432d);
    assert_eq!(
        rate(Some(&sample), interest, None, 0),
        Some(0x8000_0000_0000_0000)
    );
    assert_eq!(
        rate(Some(&sample), interest, None, 0x8000_0000_0000_0000),
        Some(0)
    );
}

#[test]
fn defaults_and_optional_override() {
    let sample = [0];
    assert_eq!(
        rate(Some(&sample), None, None, 0x3ff0_0000_0000_0000),
        Some(0x3eea_36e2_eb1c_432d)
    );
    assert_eq!(
        rate(Some(&sample), Some(0), None, 0x3ff0_0000_0000_0000),
        Some(0)
    );
    assert_eq!(
        rate(Some(&sample), None, Some(0), 0x3ff0_0000_0000_0000),
        Some(0)
    );
}

#[test]
fn finite_final_bound_and_final_scale() {
    assert_eq!(
        rate(Some(&[0x3ff0_0000_0000_0000]), None, None, 0),
        Some(0x3fa4_7ae1_47ae_147b)
    );
    assert_eq!(
        rate(Some(&[0xbff0_0000_0000_0000]), None, None, 0),
        Some(0xbfa4_7ae1_47ae_147b)
    );
    assert_eq!(
        rate(Some(&[0x3fd4_7ae1_47ae_147a]), None, None, 0),
        Some(0x3fa4_7ae1_47ae_147a)
    );
}

#[test]
fn ordered_nan_payload_and_generated_indefinite() {
    assert_eq!(
        rate(
            Some(&[0xfff0_0000_0000_0123, 0x7ff8_0000_0000_0456]),
            None,
            None,
            0
        ),
        Some(0xfff8_0000_0000_0123)
    );
    assert_eq!(
        rate(
            Some(&[0x7ff8_0000_0000_0456, 0xfff0_0000_0000_0123]),
            None,
            None,
            0
        ),
        Some(0x7ff8_0000_0000_0456)
    );
    assert_eq!(
        rate(Some(&[0x7ff0_0000_0000_0000]), None, None, 0),
        Some(0xfff8_0000_0000_0000)
    );
}

#[test]
fn unbounded_nonfinite_clamp_and_multiplier() {
    assert_eq!(
        rate(
            Some(&[0]),
            Some(0x3ff0_0000_0000_0000),
            None,
            0x7ff0_0000_0000_0000
        ),
        Some(0x3fa4_7ae1_47ae_147b)
    );
    assert_eq!(
        rate(
            Some(&[0]),
            Some(0x3ff0_0000_0000_0000),
            Some(0x7ff0_0000_0000_0000),
            0x7ff0_0000_0000_0000
        ),
        Some(0x7ff0_0000_0000_0000)
    );
    assert_eq!(
        rate(Some(&[0]), Some(0), Some(0x7ff0_0000_0000_0000), 0),
        Some(0xfff8_0000_0000_0000)
    );
}

#[test]
fn gradual_underflow_is_not_flushed() {
    assert_eq!(rate(Some(&[8]), Some(0), None, 0), Some(1));
    assert_eq!(
        rate(Some(&[0x8000_0000_0000_0008]), Some(0), None, 0),
        Some(0x8000_0000_0000_0001)
    );
    assert_eq!(rate(Some(&[4]), Some(0), None, 0), Some(0));
    assert_eq!(rate(Some(&[12]), Some(0), None, 0), Some(2));
}

#[test]
fn ordered_seven_sample_sum_has_a_frozen_rounding_result() {
    // Pre-source corpus case 0000000000000708; this is an expected constant,
    // not a call to a second implementation of the production formula.
    let samples = [0xbf1a_36e2_eb1c_432d; 7];
    assert_eq!(
        rate(Some(&samples), Some(0xbf1a_36e2_eb1c_432d), None, 0),
        Some(0xbeea_36e2_eb1c_432e)
    );
}
