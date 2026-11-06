use node115_staking_error_text as text;

#[test]
fn interval_bits_are_exactly_three_hundred() {
    assert_eq!(text::MANUAL_UNJAIL_INTERVAL_BITS, 0x4072_c000_0000_0000);
    assert_eq!(text::manual_unjail_interval_seconds().to_bits(), text::MANUAL_UNJAIL_INTERVAL_BITS);
    assert_eq!(text::manual_unjail_interval_seconds(), 300.0);
}

#[test]
fn static_arms_round_trip_and_reject_unknown_tags() {
    assert_eq!(text::STATIC_ARMS.len(), 13);
    let mut previous = 0u16;
    for arm in text::STATIC_ARMS {
        assert!(arm.discriminant > previous);
        previous = arm.discriminant;
        assert_eq!(text::static_text(arm.discriminant), Some(arm.text));
        assert!(text::is_selected_arm(arm.discriminant));
        assert!(!arm.text.is_empty());
    }
    assert_eq!(text::static_text(159), None);
    assert_eq!(text::static_text(160), None);
    assert_eq!(text::static_text(0), None);
    assert_eq!(text::static_text(417), None);
    assert!(!text::is_selected_arm(0));
    assert!(text::is_selected_arm(159));
    assert!(text::is_selected_arm(160));
}

#[test]
fn templates_keep_the_native_literal_bytes() {
    assert!(text::MANUAL_UNJAIL_TEMPLATE.windows(2).any(|pair| pair == [0xc0, 0x08]));
    assert_eq!(*text::MANUAL_UNJAIL_TEMPLATE.last().unwrap(), 0x00);
    assert_eq!(*text::JAILED_UNTIL_TEMPLATE.last().unwrap(), 0x00);
    for literal in text::MANUAL_UNJAIL_LITERALS.iter().chain(text::JAILED_UNTIL_LITERALS) {
        assert!(
            text::MANUAL_UNJAIL_TEMPLATE.windows(literal.len()).any(|w| w == literal.as_bytes())
                || text::JAILED_UNTIL_TEMPLATE.windows(literal.len()).any(|w| w == literal.as_bytes())
        );
    }
    assert_eq!(text::static_text(267), Some("Insufficient balance to delegate"));
    assert_eq!(text::static_text(282), Some("Insufficient stake"));
    assert_eq!(
        text::static_text(306),
        Some("Validator commission must be between 0 and 100%. If commission increases, it cannot exceed 1%.")
    );
}
