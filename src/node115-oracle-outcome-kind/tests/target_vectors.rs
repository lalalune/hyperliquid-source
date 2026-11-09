use node115_oracle_outcome_kind::OracleOutcomeKind;

const VISITOR_CASES: &str =
    include_str!("../../../research/work-items/risk-outcome-kind-codec-115/visitor-cases.tsv");

fn decode_hex(value: &str) -> Vec<u8> {
    if value == "-" {
        return Vec::new();
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16).unwrap();
            let low = (pair[1] as char).to_digit(16).unwrap();
            ((high << 4) | low) as u8
        })
        .collect()
}

fn expected_kind(name: &str) -> Option<OracleOutcomeKind> {
    match name {
        "StandaloneOutcome" => Some(OracleOutcomeKind::StandaloneOutcome),
        "Question" => Some(OracleOutcomeKind::Question),
        "QuestionOutcome" => Some(OracleOutcomeKind::QuestionOutcome),
        "-" => None,
        other => panic!("unexpected fixture name: {other}"),
    }
}

#[test]
fn matches_every_byte_visitor_case_interpreted_from_node115() {
    let mut rows = VISITOR_CASES.lines();
    assert_eq!(
        rows.next(),
        Some("input_hex\tlength\t0x25d3a80\t0x25d3ca0\t0x44647c0\t0x44649e0\t0x54797f0\t0x5479a10\toutcome_kind\tverdict")
    );

    let mut count = 0;
    for row in rows {
        let columns: Vec<_> = row.split('\t').collect();
        assert_eq!(columns.len(), 10, "fixture row {row}");
        let input = decode_hex(columns[0]);
        let expected = expected_kind(columns[8]);
        let got = OracleOutcomeKind::from_bytes(&input);

        match (expected, got) {
            (Some(kind), Ok(actual)) => {
                assert_eq!(actual, kind, "input {}", columns[0]);
                assert_eq!(
                    actual.tagged_result_word(),
                    0x09 | ((kind.tag() as u64) << 8)
                );
                for output in &columns[2..8] {
                    assert_eq!(
                        u64::from_str_radix(output.strip_prefix("ok:0x").unwrap(), 16).unwrap(),
                        kind.tagged_result_word(),
                        "fixture output for {}",
                        columns[0]
                    );
                }
            }
            (None, Err(error)) => {
                assert_eq!(
                    error.value(),
                    String::from_utf8_lossy(&input).as_ref(),
                    "unknown value for input {}",
                    columns[0]
                );
                let has_invalid_utf8 = core::str::from_utf8(&input).is_err();
                for (index, output) in columns[2..8].iter().enumerate() {
                    let expected = if index % 2 == 0 && has_invalid_utf8 {
                        "err:lossy:free"
                    } else {
                        "err"
                    };
                    assert_eq!(*output, expected, "input {}", columns[0]);
                }
            }
            (expected, got) => panic!(
                "visitor result disagrees for {}: expected {expected:?}, got {got:?}",
                columns[0]
            ),
        }
        assert_eq!(
            columns[9], "match",
            "target-interpreter verdict for {}",
            columns[0]
        );
        count += 1;
    }
    assert_eq!(count, 2333);
}

#[test]
fn string_visitor_preserves_borrowed_unknown_text() {
    let input = "question";
    let error = OracleOutcomeKind::from_name(input).unwrap_err();
    assert_eq!(error.value(), input);
    assert!(error.is_borrowed());
}
