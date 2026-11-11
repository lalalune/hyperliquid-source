use node115_spot_mark_codec::SpotMarkKind;

const VISITORS: &str =
    include_str!("../../../research/work-items/RE-015-spot-mark-codec-115/visitor-cases.tsv");
const SERIALIZERS: &str =
    include_str!("../../../research/work-items/RE-015-spot-mark-codec-115/serializer-cases.tsv");

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
fn all_target_visitor_rows_match_exact_names() {
    let mut rows = 0usize;
    for line in VISITORS.lines().skip(1) {
        let cols: Vec<_> = line.split('\t').collect();
        assert_eq!(cols.len(), 7, "malformed fixture row: {line}");
        let input = parse_hex(cols[0]);
        let value = core::str::from_utf8(&input)
            .ok()
            .and_then(SpotMarkKind::from_name);
        assert_eq!(cols[5], value.map_or("-", SpotMarkKind::name));

        for i in 0..3 {
            if let Some(value) = value {
                assert_eq!(
                    cols[2 + i],
                    format!("ok:{:#x}", value.tagged_result_word()),
                    "visitor {i}, input {}",
                    cols[0]
                );
            } else {
                assert!(
                    cols[2 + i].starts_with("err:"),
                    "visitor accepted {}",
                    cols[0]
                );
            }
        }
        assert_eq!(cols[6], "match");
        rows += 1;
    }
    assert_eq!(rows, 5_162);
}

#[test]
fn all_target_serializer_rows_match_fixstr_dispatch() {
    let mut rows = 0usize;
    for line in SERIALIZERS.lines().skip(1) {
        let cols: Vec<_> = line.split('\t').collect();
        assert_eq!(cols.len(), 10, "malformed fixture row: {line}");
        let tag: u8 = cols[1].parse().unwrap();
        let value = SpotMarkKind::from_serializer_tag(tag);
        let mut output = b"previous".to_vec();
        value.append_msgpack_fixstr(&mut output);
        assert_eq!(output[8..], parse_hex(cols[4]));
        assert_eq!(
            cols[6].parse::<usize>().unwrap(),
            cols[3].parse::<usize>().unwrap() + output.len() - 8
        );
        assert_eq!(cols[7], "0x8000000000000004");
        assert_eq!(cols[8], value.name());
        assert_eq!(cols[9], "match");
        rows += 1;
    }
    assert_eq!(rows, 1_335);
}

#[test]
fn ordinary_names_keep_declaration_tags() {
    for (tag, value) in SpotMarkKind::ALL.into_iter().enumerate() {
        assert_eq!(value.tag(), tag as u8);
        assert_eq!(SpotMarkKind::from_name(value.name()), Some(value));
        assert_eq!(value.tagged_result_word(), 0x09 | ((tag as u64) << 8));
    }
    assert_eq!(SpotMarkKind::from_name("spot"), None);
    assert_eq!(SpotMarkKind::from_name("ExternalPerpExtra"), None);
}
