use node115_evm_precompile_outcome_names::ReadPrecompileOutcomeName;

const VISITORS: &str =
    include_str!("../../../research/work-items/evm-call-outcome-codec-115/visitor-cases.tsv");

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
fn all_target_visitor_rows_match_exact_variant_names() {
    let mut rows = 0usize;
    for line in VISITORS.lines().skip(1) {
        let cols: Vec<_> = line.split('\t').collect();
        assert_eq!(cols.len(), 6, "malformed fixture row: {line}");
        let input = parse_hex(cols[0]);
        let outcome = core::str::from_utf8(&input)
            .ok()
            .and_then(ReadPrecompileOutcomeName::from_name);
        assert_eq!(
            cols[4],
            outcome.map_or("-", ReadPrecompileOutcomeName::name)
        );

        for visitor in 0..2 {
            if let Some(outcome) = outcome {
                assert_eq!(
                    cols[2 + visitor],
                    format!("ok:{:#x}", outcome.tagged_result_word()),
                    "visitor {visitor}, input {}",
                    cols[0]
                );
            } else {
                assert!(
                    cols[2 + visitor].starts_with("err"),
                    "visitor accepted {}",
                    cols[0]
                );
            }
        }
        assert_eq!(cols[5], "match");
        rows += 1;
    }
    assert_eq!(rows, 1_792);
}

#[test]
fn tags_and_variant_names_are_fixed() {
    for (tag, outcome) in ReadPrecompileOutcomeName::ALL.into_iter().enumerate() {
        assert_eq!(outcome.tag(), tag as u8);
        assert_eq!(
            ReadPrecompileOutcomeName::from_name(outcome.name()),
            Some(outcome)
        );
        assert_eq!(outcome.tagged_result_word(), 0x09 | ((tag as u64) << 8));
    }
    assert_eq!(ReadPrecompileOutcomeName::from_name("ok"), None);
    assert_eq!(
        ReadPrecompileOutcomeName::from_name("UnexpectedErrorExtra"),
        None
    );
}
