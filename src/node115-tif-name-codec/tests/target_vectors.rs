use node115_tif_name_codec::Tif;

const VISITOR_CASES: &str =
    include_str!("../../../research/work-items/RE-006-tif-codec-115/visitor-cases.tsv");
const SERIALIZER_CASES: &str =
    include_str!("../../../research/work-items/RE-006-tif-codec-115/serializer-cases.tsv");

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

fn kind(name: &str) -> Option<Tif> {
    match name {
        "Alo" => Some(Tif::Alo),
        "Ioc" => Some(Tif::Ioc),
        "Gtc" => Some(Tif::Gtc),
        "FrontendMarket" => Some(Tif::FrontendMarket),
        "LiquidationMarket" => Some(Tif::LiquidationMarket),
        "-" => None,
        other => panic!("unexpected fixture name: {other}"),
    }
}

#[test]
fn serializers_match_all_target_interpreter_wire_vectors() {
    let mut rows = SERIALIZER_CASES.lines();
    assert_eq!(
        rows.next(),
        Some("serializer\ttag\tcapacity\tlength\tappended_hex\tgrow_calls\tfinal_length\tresult_word\tarm\tverdict")
    );

    let mut count = 0;
    for row in rows {
        let columns: Vec<_> = row.split('\t').collect();
        assert_eq!(columns.len(), 10, "fixture row {row}");
        let tif = kind(columns[8]).expect("serializer arm name");
        assert_eq!(tif.tag(), columns[1].parse::<u8>().unwrap());
        let mut output = vec![0x55; columns[3].parse().unwrap()];
        let prefix_length = output.len();
        assert_eq!(tif.write_msgpack(&mut output), 0x8000_0000_0000_0004);
        assert_eq!(&output[prefix_length..], decode_hex(columns[4]));
        assert_eq!(output.len(), columns[6].parse::<usize>().unwrap());
        assert_eq!(
            u64::from_str_radix(columns[7].strip_prefix("0x").unwrap(), 16).unwrap(),
            0x8000_0000_0000_0004
        );
        assert_eq!(columns[9], "match");
        count += 1;
    }
    assert_eq!(count, 1260);
}

#[test]
fn visitors_match_all_target_interpreter_name_vectors() {
    let mut rows = VISITOR_CASES.lines();
    assert_eq!(
        rows.next(),
        Some("input_hex\tlength\t0x25ce8d0\t0x25ceb10\t0x25ced60\t0x25cee60\t0x4446ea0\t0x44470f0\t0x4447330\t0x4447430\t0x5171010\t0x5171260\treconstruction\tverdict")
    );
    let result_forms = [
        true, false, true, false, false, true, true, false, false, false,
    ];
    let byte_visitors = [
        true, true, false, false, true, true, false, false, true, false,
    ];

    let mut count = 0;
    for row in rows {
        let columns: Vec<_> = row.split('\t').collect();
        assert_eq!(columns.len(), 14, "fixture row {row}");
        let input = decode_hex(columns[0]);
        let expected = kind(columns[12]);
        let got = Tif::from_bytes(&input);

        match (expected, got) {
            (Some(tif), Ok(actual)) => {
                assert_eq!(actual, tif, "input {}", columns[0]);
                assert_eq!(Tif::from_name(tif.as_str()), Ok(tif));
                for index in 0..10 {
                    let word = if result_forms[index] {
                        tif.tag() as u64
                    } else {
                        tif.tagged_result_word()
                    };
                    let observed =
                        u64::from_str_radix(columns[index + 2].strip_prefix("ok:0x").unwrap(), 16)
                            .unwrap();
                    assert_eq!(observed, word, "visitor {index}, input {}", columns[0]);
                }
            }
            (None, Err(error)) => {
                assert_eq!(
                    error.value(),
                    String::from_utf8_lossy(&input).as_ref(),
                    "unknown value for input {}",
                    columns[0]
                );
                let invalid_utf8 = core::str::from_utf8(&input).is_err();
                for index in 0..10 {
                    let expected_status = if byte_visitors[index] && invalid_utf8 {
                        "err:lossy:free"
                    } else {
                        "err"
                    };
                    assert_eq!(columns[index + 2], expected_status, "visitor {index}");
                }
                assert_eq!(error.is_borrowed(), !invalid_utf8);
            }
            (expected, got) => panic!(
                "visitor result disagrees for {}: expected {expected:?}, got {got:?}",
                columns[0]
            ),
        }
        assert_eq!(columns[13], "match", "target-interpreter verdict");
        count += 1;
    }
    assert_eq!(count, 2352);
}
