use node115_chain_name_codec::ChainName;

const VISITORS: &str =
    include_str!("../../../research/work-items/RE-015-chain-codec-115/visitor-cases.tsv");
const SERIALIZERS: &str =
    include_str!("../../../research/work-items/RE-015-chain-codec-115/serializer-cases.tsv");
const TAGGED_VISITORS: [bool; 5] = [true, true, true, false, false];

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
fn all_target_visitor_rows_match_exact_name_rules() {
    let mut rows = 0usize;
    for line in VISITORS.lines().skip(1) {
        let cols: Vec<_> = line.split('\t').collect();
        assert_eq!(cols.len(), 9, "malformed fixture row: {line}");
        let bytes = parse_hex(cols[0]);
        let chain = core::str::from_utf8(&bytes)
            .ok()
            .and_then(ChainName::from_name);
        assert_eq!(cols[7], chain.map_or("-", ChainName::name));

        for (i, tagged) in TAGGED_VISITORS.iter().copied().enumerate() {
            if let Some(chain) = chain {
                let expected = if tagged {
                    format!("ok:{:#x}", chain.tagged_result_word())
                } else {
                    format!("ok:{:#x}", chain.tag())
                };
                assert_eq!(cols[2 + i], expected, "visitor {i}, input {}", cols[0]);
            } else {
                assert!(
                    cols[2 + i].starts_with("err:"),
                    "visitor accepted {}",
                    cols[0]
                );
            }
        }
        assert_eq!(cols[8], "match");
        rows += 1;
    }
    assert_eq!(rows, 6_675);
}

#[test]
fn all_target_serializer_rows_match_fixstr_bytes() {
    let mut rows = 0usize;
    for line in SERIALIZERS.lines().skip(1) {
        let cols: Vec<_> = line.split('\t').collect();
        assert_eq!(cols.len(), 9, "malformed fixture row: {line}");
        let tag: u8 = cols[1].parse().unwrap();
        let chain = ChainName::from_tag(tag).unwrap();
        let mut output = b"previous".to_vec();
        chain.append_msgpack_fixstr(&mut output);
        assert_eq!(output[8..], parse_hex(cols[4]));
        assert_eq!(
            cols[6].parse::<usize>().unwrap(),
            cols[3].parse::<usize>().unwrap() + output.len() - 8
        );
        assert_eq!(cols[7], "0x8000000000000004");
        assert_eq!(cols[8], "match");
        rows += 1;
    }
    assert_eq!(rows, 360);
}

#[test]
fn exact_names_tags_and_success_words_are_bounded() {
    for chain in ChainName::ALL {
        assert_eq!(ChainName::from_tag(chain.tag()), Some(chain));
        assert_eq!(ChainName::from_name(chain.name()), Some(chain));
        assert_eq!(
            chain.tagged_result_word(),
            0x09 | ((chain.tag() as u64) << 8)
        );
    }
    assert_eq!(ChainName::from_tag(4), None);
    assert_eq!(ChainName::from_name("local"), None);
    assert_eq!(ChainName::from_name("Mainnet-extra"), None);
}
