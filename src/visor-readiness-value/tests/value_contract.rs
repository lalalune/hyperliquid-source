use visor_readiness_value::{Timestamp, is_strictly_past_deadline};

fn value(y: i32, o: u16, s: u32, n: u32) -> Timestamp {
    Timestamp::from_parts(y, o, s, n).unwrap()
}

#[test]
fn parts_admission_is_explicit() {
    assert!(Timestamp::from_parts(-262143, 1, 0, 0).is_some());
    assert!(Timestamp::from_parts(262142, 365, 86399, 999999999).is_some());
    for (y, o, s, n) in [
        (-262144, 1, 0, 0),
        (262143, 1, 0, 0),
        (1970, 0, 0, 0),
        (1900, 366, 0, 0),
        (2000, 367, 0, 0),
        (1970, 1, 86400, 0),
        (1970, 1, 0, 1000000000),
    ] {
        assert!(Timestamp::from_parts(y, o, s, n).is_none());
    }
}

#[test]
fn sample_epoch_and_day_boundary() {
    assert_eq!(
        Timestamp::from_clock_sample(0, 0),
        Some(value(1970, 1, 0, 0))
    );
    assert_eq!(
        Timestamp::from_clock_sample(86399, 999999999),
        Some(value(1970, 1, 86399, 999999999))
    );
    assert_eq!(
        Timestamp::from_clock_sample(86400, 1),
        Some(value(1970, 2, 0, 1))
    );
}

#[test]
fn sample_range_and_fraction_refusal() {
    assert_eq!(
        Timestamp::from_clock_sample(8210266876799, 999999999),
        Some(value(262142, 365, 86399, 999999999))
    );
    for (s, n) in [
        (-1, 0),
        (8210266876800, 0),
        (0, 1000000000),
        (i64::MAX, u64::MAX),
    ] {
        assert!(Timestamp::from_clock_sample(s, n).is_none());
    }
}

#[test]
fn common_and_leap_year_rollovers() {
    for (y, last) in [
        (-400, 366),
        (-100, 365),
        (-1, 365),
        (0, 366),
        (1900, 365),
        (2000, 366),
        (2100, 365),
        (2400, 366),
    ] {
        assert_eq!(
            value(y, last, 86340, 7).deadline_60(),
            value(y + 1, 1, 0, 7)
        );
    }
}

#[test]
fn time_carry_keeps_ordinary_nanos() {
    assert_eq!(
        value(2000, 60, 86339, 999999999).deadline_60(),
        value(2000, 60, 86399, 999999999)
    );
    assert_eq!(
        value(2000, 60, 86340, 1).deadline_60(),
        value(2000, 61, 0, 1)
    );
    assert_eq!(
        value(2000, 60, 86399, 500000000).deadline_60(),
        value(2000, 61, 59, 500000000)
    );
}

#[test]
fn saturation_is_ordinary_maximum() {
    let maximum = value(262142, 365, 86399, 999999999);
    assert_eq!(maximum.raw_words(), (2147473118, 86399, 999999999));
    assert_eq!(value(262142, 365, 86340, 0).deadline_60(), maximum);
    assert_eq!(maximum.deadline_60(), maximum);
    assert!(!is_strictly_past_deadline(maximum, maximum));
}

#[test]
fn strict_comparison_handles_equality_and_nanos() {
    let source = value(2000, 1, 0, 1);
    assert!(!is_strictly_past_deadline(value(2000, 1, 60, 0), source));
    assert!(!is_strictly_past_deadline(value(2000, 1, 60, 1), source));
    assert!(is_strictly_past_deadline(value(2000, 1, 60, 2), source));
}

#[test]
fn signed_dates_and_cycle_flags() {
    assert_eq!(value(0, 1, 0, 0).raw_words().0, 20);
    assert_eq!(value(400, 1, 0, 0).raw_words().0, 3276820);
    assert!(is_strictly_past_deadline(
        value(0, 1, 0, 0),
        value(-1, 1, 0, 0)
    ));
    assert!(!is_strictly_past_deadline(
        value(-1, 1, 0, 0),
        value(0, 1, 0, 0)
    ));
}
