use node115_margin_mode_codec::MarginMode;

const VISITORS: &str =
    include_str!("../../../research/work-items/RE-007-margin-mode-codec-115/visitor-cases.tsv");
const SERIALIZERS: &str =
    include_str!("../../../research/work-items/RE-007-margin-mode-codec-115/serializer-cases.tsv");
const TAGGED_VISITORS: [bool; 8] = [false, true, true, true, false, true, true, true];

fn parse_hex(input: &str) -> Vec<u8> {
    if input == "-" {
        return Vec::new();
    }
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digits = core::str::from_utf8(pair).unwrap();
            u8::from_str_radix(digits, 16).unwrap()
        })
        .collect()
}

#[test]
fn all_target_visitors_match_exact_names_and_result_forms() {
    let mut rows = 0usize;
    for line in VISITORS.lines().skip(1) {
        let cols: Vec<_> = line.split('\t').collect();
        assert_eq!(cols.len(), 12, "malformed fixture row: {line}");
        let input = parse_hex(cols[0]);
        let mode = core::str::from_utf8(&input)
            .ok()
            .and_then(MarginMode::from_name);
        assert_eq!(cols[10], mode.map_or("-", MarginMode::name));

        for (i, tagged) in TAGGED_VISITORS.iter().copied().enumerate() {
            if let Some(mode) = mode {
                let expected = if tagged {
                    format!("ok:{:#x}", mode.tagged_result_word())
                } else {
                    format!("ok:{:#x}", mode.tag())
                };
                assert_eq!(cols[2 + i], expected, "visitor {i}, input {}", cols[0]);
            } else {
                assert!(
                    cols[2 + i].starts_with("err"),
                    "visitor accepted {}",
                    cols[0]
                );
            }
        }
        assert_eq!(cols[11], "match");
        rows += 1;
    }
    assert_eq!(rows, 1_580);
}

#[test]
fn all_target_serializers_match_fixstr_tag_dispatch() {
    let mut rows = 0usize;
    for line in SERIALIZERS.lines().skip(1) {
        let cols: Vec<_> = line.split('\t').collect();
        assert_eq!(cols.len(), 10, "malformed fixture row: {line}");
        let tag: u8 = cols[1].parse().unwrap();
        let mode = MarginMode::from_serializer_tag(tag);
        let mut output = b"previous".to_vec();
        mode.append_msgpack_fixstr(&mut output);
        assert_eq!(output[8..], parse_hex(cols[4]));
        assert_eq!(
            cols[6].parse::<usize>().unwrap(),
            cols[3].parse::<usize>().unwrap() + output.len() - 8
        );
        assert_eq!(cols[7], "0x8000000000000004");
        assert_eq!(cols[8], mode.name());
        assert_eq!(cols[9], "match");
        rows += 1;
    }
    assert_eq!(rows, 2_274);
}

#[test]
fn declaration_tags_names_and_tagged_words_match() {
    for mode in MarginMode::ALL {
        assert_eq!(
            mode.tag(),
            MarginMode::ALL.iter().position(|m| *m == mode).unwrap() as u8
        );
        assert_eq!(MarginMode::from_name(mode.name()), Some(mode));
        assert_eq!(mode.tagged_result_word(), 0x09 | ((mode.tag() as u64) << 8));
    }
    assert_eq!(MarginMode::from_name("NoCross"), None);
    assert_eq!(MarginMode::from_name("strictIsolated-extra"), None);
    assert_eq!(
        MarginMode::from_serializer_tag(255),
        MarginMode::StrictIsolated
    );
}
