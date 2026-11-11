use node115_hip3_disabled_state_codec::DisabledState;

const CASES: [(u8, &str, u64); 4] = [
    (0, "Na", 0x09),
    (1, "UserDisabled", 0x109),
    (2, "ValidatorDisabled", 0x209),
    (3, "m", 0x309),
];

#[test]
fn tags_names_and_tagged_visitor_words_match_packet() {
    for (tag, name, word) in CASES {
        let state = DisabledState::from_tag(tag).unwrap();
        assert_eq!(state.name(), name);
        assert_eq!(DisabledState::from_name(name), Some(state));
        assert_eq!(state.tagged_result_word(), word);
    }
    assert_eq!(DisabledState::from_tag(4), None);
    assert_eq!(DisabledState::from_name("userdisabled"), None);
    assert_eq!(DisabledState::from_name("UserDisabledx"), None);
}

#[test]
fn json_writer_appends_exact_unit_variant_text() {
    for (_, name, _) in CASES {
        let state = DisabledState::from_name(name).unwrap();
        let mut output = b"prefix:".to_vec();
        state.append_json(&mut output);
        assert_eq!(output, format!("prefix:\"{name}\"").as_bytes());
    }
}
