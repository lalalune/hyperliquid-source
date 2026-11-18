use node115_restart_delay::{WaitPlan, delay_seconds, first_wait};
use std::time::Duration;

#[test]
fn initialized_cap_sequence_and_counter_saturation() {
    for (index, expected) in [0, 1, 3, 7, 15, 29, 29].into_iter().enumerate() {
        assert_eq!(delay_seconds(index as u64, 30.0), f64::from(expected));
    }
    for counter in [1023, 1024, i32::MAX as u64, i32::MAX as u64 + 1, u64::MAX] {
        assert_eq!(
            first_wait(counter, 30.0),
            WaitPlan::Timer(Duration::from_secs(29))
        );
    }
}

#[test]
fn cap_and_finite_guard_precede_duration_conversion() {
    for cap in [f64::NEG_INFINITY, -30.0, -0.0, 0.25, 1.0] {
        assert_eq!(delay_seconds(10, cap).to_bits(), 0);
    }
    for cap in [f64::NAN, f64::INFINITY] {
        assert_eq!(delay_seconds(4, cap), 15.0);
        assert_eq!(first_wait(64, cap), WaitPlan::OutOfRange);
        assert_eq!(first_wait(1023, cap), WaitPlan::OutOfRange);
        assert_eq!(first_wait(1024, cap), WaitPlan::Immediate);
    }
    let limit = (u64::MAX as f64).to_bits();
    let largest = f64::from_bits(limit - 1);
    assert_eq!(
        first_wait(80, largest),
        WaitPlan::Timer(Duration::from_secs(u64::MAX - 2047))
    );
    assert_eq!(first_wait(80, f64::from_bits(limit)), WaitPlan::OutOfRange);
}

#[test]
fn rounded_zero_still_constructs_a_timer() {
    assert_eq!(first_wait(10, 1.0), WaitPlan::Immediate);
    assert_eq!(
        first_wait(10, f64::from_bits(1.0f64.to_bits() + 1)),
        WaitPlan::Timer(Duration::ZERO)
    );
    assert_eq!(
        first_wait(10, f64::from_bits(2.0f64.to_bits() - 1)),
        WaitPlan::Timer(Duration::from_secs(1))
    );
}

#[test]
fn half_nanosecond_ties_across_seconds_use_even_neighbor() {
    // q / 1024 seconds gives exactly q * 976562.5 ns. Integer arithmetic
    // computes the expected duration independently of the Rust float converter.
    for q in 1u64..4096 {
        let (whole, half) = (q * 1_953_125 / 2, q % 2);
        let rounded = whole + (half & (whole & 1));
        assert_eq!(
            first_wait(10, 1.0 + q as f64 / 1024.0),
            WaitPlan::Timer(Duration::from_nanos(rounded))
        );
    }
}
