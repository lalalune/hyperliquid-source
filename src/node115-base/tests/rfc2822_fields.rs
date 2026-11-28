use node115_base::rfc2822::{ParseError, ParsedFields};

#[test]
fn builds_fields_and_retains_the_unconsumed_suffix() {
    let mut fields = ParsedFields::default();
    let rest = fields
        .parse("Tue, 02 Jan 24 23:04:60 -0530 (a (nested) b) (x\\)y) tail")
        .unwrap();
    assert_eq!(rest, " tail");
    assert_eq!(
        fields,
        ParsedFields {
            weekday: Some(1),
            day: Some(2),
            month: Some(1),
            year: Some(2024),
            hour_div_12: Some(1),
            hour_mod_12: Some(11),
            minute: Some(4),
            second: Some(60),
            offset_seconds: Some(-19_800)
        }
    );
}

#[test]
fn partial_record_keeps_successful_writes_before_a_conflict() {
    let mut fields = ParsedFields {
        minute: Some(3),
        ..Default::default()
    };
    assert_eq!(
        fields.parse("2 Jan 2024 03:04 GMT"),
        Err(ParseError::Impossible)
    );
    assert_eq!(fields.hour_mod_12, Some(3));
    assert_eq!(fields.minute, Some(3));
    assert_eq!(fields.offset_seconds, None);
}

#[test]
fn year_window_military_zones_and_optional_seconds() {
    for (year, expected) in [("49", 2049), ("50", 1950), ("100", 2000), ("0050", 50)] {
        let value = format!("1\u{a0}Jan {year} 12 : 59 A");
        let mut fields = ParsedFields::default();
        assert_eq!(fields.parse(&value), Ok(""));
        assert_eq!(fields.year, Some(expected));
        assert_eq!(fields.second, None);
        assert_eq!(fields.offset_seconds, Some(0));
    }
    let mut fields = ParsedFields::default();
    assert_eq!(fields.parse("1 Jan 24 00:00 J"), Err(ParseError::Invalid));
}

#[test]
fn reports_distinct_failures_and_leaves_an_unclosed_comment() {
    use ParseError::*;
    for (text, error) in [
        ("", TooShort),
        ("0 Jan 24 01:00 GMT", OutOfRange),
        ("Mon 1 Jan 24 12:00 GMT", Invalid),
        ("1 Jan 24 24:00 GMT", OutOfRange),
        ("1 Jan 24 12:00 +0060", OutOfRange),
        ("1 Jan 24 00:00: 30 GMT", Invalid),
    ] {
        assert_eq!(ParsedFields::default().parse(text), Err(error), "{text}");
    }
    assert_eq!(
        ParsedFields::default().parse("1 Jan 24 00:00 EDT (open"),
        Ok(" (open")
    );
}
