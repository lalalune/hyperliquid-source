use node115_checkpoint_clock_text::{
    ClockIngressError, parse_checkpoint_clock, render_checkpoint_clock, stage_decoded_clock_pair,
};

#[test]
fn text_maps_to_native_clock_words_on_selected_paths() {
    for (text, expected) in [
        ("2026-01-02T03:04:05", (0x00fd_402a, 11_045, 0)),
        (
            "2000-02-29T12:34:56.000123456",
            (0x00fa_03c4, 45_296, 123_456),
        ),
        (
            "2016-12-31T23:59:60.123",
            (0x00fc_16e3, 86_399, 1_123_000_000),
        ),
    ] {
        let current = parse_checkpoint_clock(text).unwrap();
        let words = (
            current.date.packed as u32,
            current.seconds_of_day,
            current.nanoseconds,
        );
        assert_eq!(words, expected);
        assert_eq!(
            render_checkpoint_clock(words.0, words.1, words.2)
                .unwrap()
                .as_str(),
            text
        );
    }
    assert_eq!(
        parse_checkpoint_clock("1970-01-01T00:00:00.1")
            .unwrap()
            .nanoseconds,
        100_000_000
    );
}

#[test]
fn unsupported_text_has_no_clock_projection() {
    for text in [
        "1900-02-29T12:00:00",
        "2000-02-30T12:00:00",
        "2000-13-01T12:00:00",
        "2000-01-00T12:00:00",
        "2000-01-01T24:00:00",
        "2000-01-01T23:60:00",
        "2000-01-01T23:59:61",
        "2000-01-01T00:00:00.",
        "2000-01-01T00:00:00.1234567890",
        "2000-01-01T00:00:00Z",
        "2000-01-01 00:00:00",
        "0000-01-01T00:00:00",
    ] {
        assert!(parse_checkpoint_clock(text).is_none(), "{text}");
    }
}

#[test]
fn decoded_stage_checks_height_and_updates_both_clocks_together() {
    const CURRENT: &str = "2026-01-02T03:04:05";
    const PREVIOUS: &str = "2000-02-29T12:34:56.000123456";
    let mut image = vec![0xa5; 0x27a8];
    image[0x28..0x30].copy_from_slice(&19_u64.to_le_bytes());
    let before = image.clone();
    assert_eq!(
        stage_decoded_clock_pair(&mut image, 19, CURRENT, "missing"),
        Err(ClockIngressError::PreviousClock)
    );
    assert_eq!(
        stage_decoded_clock_pair(&mut image, 20, CURRENT, PREVIOUS),
        Err(ClockIngressError::HeightMismatch {
            expected: 20,
            actual: 19
        })
    );
    assert_eq!(image, before);

    stage_decoded_clock_pair(&mut image, 19, CURRENT, PREVIOUS).unwrap();
    let words = [0x00fd_402a_u32, 11_045, 0, 0x00fa_03c4, 45_296, 123_456];
    let expected: Vec<_> = words.into_iter().flat_map(u32::to_le_bytes).collect();
    assert_eq!(&image[0x60..0x78], expected);
    assert_eq!(image[..0x60], before[..0x60]);
    assert_eq!(image[0x78..], before[0x78..]);
}
