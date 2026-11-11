use node115_borrow_lend_codec::{BorrowLendField, Operation};

const VISITORS: &str =
    include_str!("../../../research/work-items/RE-007-borrow-lend-codec-115/visitor-cases.tsv");
const SERIALIZERS: &str =
    include_str!("../../../research/work-items/RE-007-borrow-lend-codec-115/serializer-cases.tsv");
const OP_FORMS: [bool; 10] = [
    false, true, false, true, true, false, true, false, true, true,
];
const FIELD_FORMS: [bool; 8] = [false, true, true, true, false, true, true, true];

fn parse_hex(input: &str) -> Vec<u8> {
    if input == "-" {
        return Vec::new();
    }
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let s = core::str::from_utf8(pair).unwrap();
            u8::from_str_radix(s, 16).unwrap()
        })
        .collect()
}

fn expected_success(tag: u8, tagged: bool) -> String {
    if tagged {
        format!("ok:{:#x}", 0x09_u64 | ((tag as u64) << 8))
    } else {
        format!("ok:{:#x}", tag)
    }
}

#[test]
fn all_target_visitor_rows_match_exact_operation_and_field_rules() {
    let mut rows = 0usize;
    for line in VISITORS.lines().skip(1) {
        let cols: Vec<_> = line.split('\t').collect();
        assert_eq!(cols.len(), 23, "malformed fixture row: {line}");
        let bytes = parse_hex(cols[0]);
        let text = core::str::from_utf8(&bytes).ok();
        let operation = text.and_then(Operation::from_name);
        let field = text.and_then(BorrowLendField::from_name);
        assert_eq!(cols[20], operation.map_or("-", Operation::name));
        assert_eq!(cols[21], field.map_or("-", BorrowLendField::name));

        for (i, tagged) in OP_FORMS.iter().copied().enumerate() {
            if let Some(op) = operation {
                assert_eq!(
                    cols[2 + i],
                    expected_success(op.tag(), tagged),
                    "operation visitor column {} input {}",
                    i,
                    cols[0]
                );
            } else {
                assert!(
                    cols[2 + i].starts_with("err"),
                    "operation visitor accepted input {}",
                    cols[0]
                );
            }
        }
        for (i, tagged) in FIELD_FORMS.iter().copied().enumerate() {
            if let Some(key) = field {
                assert_eq!(
                    cols[12 + i],
                    expected_success(key.tag(), tagged),
                    "field visitor column {} input {}",
                    i,
                    cols[0]
                );
            } else {
                assert!(
                    cols[12 + i].starts_with("err"),
                    "field visitor accepted input {}",
                    cols[0]
                );
            }
        }
        assert_eq!(cols[22], "match");
        rows += 1;
    }
    assert_eq!(rows, 2_682);
}

#[test]
fn all_target_serializer_rows_match_msgpack_fixstr_bytes() {
    let mut rows = 0usize;
    for line in SERIALIZERS.lines().skip(1) {
        let cols: Vec<_> = line.split('\t').collect();
        assert_eq!(cols.len(), 10, "malformed fixture row: {line}");
        let tag: u8 = cols[1].parse().unwrap();
        let operation = Operation::from_tag(tag).unwrap();
        let mut output = b"prior".to_vec();
        operation.append_msgpack_fixstr(&mut output);
        assert_eq!(output[5..], parse_hex(cols[4]));
        assert_eq!(
            cols[6].parse::<usize>().unwrap(),
            cols[3].parse::<usize>().unwrap() + output.len() - 5
        );
        assert_eq!(cols[7], "0x8000000000000004");
        assert_eq!(cols[9], "match");
        rows += 1;
    }
    assert_eq!(rows, 1_008);
}

#[test]
fn exact_names_and_invalid_tags_are_bounded() {
    for operation in Operation::ALL {
        assert_eq!(Operation::from_tag(operation.tag()), Some(operation));
        assert_eq!(Operation::from_name(operation.name()), Some(operation));
        assert_eq!(
            operation.tagged_result_word(),
            0x09 | ((operation.tag() as u64) << 8)
        );
    }
    for field in BorrowLendField::ALL {
        assert_eq!(BorrowLendField::from_name(field.name()), Some(field));
        assert_eq!(
            field.tagged_result_word(),
            0x09 | ((field.tag() as u64) << 8)
        );
    }
    assert_eq!(Operation::from_tag(4), None);
    assert_eq!(Operation::from_name("Borrow"), None);
    assert_eq!(BorrowLendField::from_name("unknown"), None);
}
