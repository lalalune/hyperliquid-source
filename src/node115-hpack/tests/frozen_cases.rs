use node115_hpack::encode;

const CASES: &str =
    include_str!("../../../research/work-items/transport-hpack-encode-115/cases-sample.tsv");

fn hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);

    (0..value.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&value[offset..offset + 2], 16).unwrap())
        .collect()
}

#[test]
fn sampled_cases_match_encoder() {
    for (line_index, line) in CASES.lines().enumerate().skip(1) {
        let fields: Vec<&str> = line.split('\t').collect();
        assert_eq!(fields.len(), 9, "line {}", line_index + 1);

        let case_id = fields[0];
        let kind = fields[1];
        let index: usize = fields[2].parse().unwrap();
        let sensitive = fields[3] == "1";
        let prefix = hex(fields[4]);
        let input = hex(fields[6]);
        let expected = hex(fields[7]);

        let mut output = prefix.clone();

        if kind.starts_with("huffman") {
            encode::huffman_encode(&input, &mut output);
        } else if kind.starts_with("string") {
            encode::encode_str(&input, &mut output);
        } else if kind.starts_with("literal") {
            encode::encode_literal_name_index(index, &input, sensitive, &mut output);
        } else {
            panic!("unknown case kind {kind} on line {}", line_index + 1);
        }

        assert_eq!(
            &output[..prefix.len()],
            prefix.as_slice(),
            "prefix changed for case {case_id} on line {}",
            line_index + 1
        );
        assert_eq!(
            &output[prefix.len()..],
            expected.as_slice(),
            "output mismatch for case {case_id} on line {}",
            line_index + 1
        );
    }
}

#[test]
fn rfc_7541_appendix_c4_vectors() {
    let huffman_vectors = [
        ("www.example.com", "f1e3c2e5f23a6ba0ab90f4ff"),
        ("no-cache", "a8eb10649cbf"),
        ("custom-key", "25a849e95ba97d7f"),
        ("custom-value", "25a849e95bb8e8b4bf"),
        ("302", "6402"),
        ("private", "aec3771a4b"),
        (
            "Mon, 21 Oct 2013 20:13:21 GMT",
            "d07abe941054d444a8200595040b8166e082a62d1bff",
        ),
        (
            "https://www.example.com",
            "9d29ad171863c78f0b97c8e9ae82ae43d3",
        ),
    ];

    for (input, expected) in huffman_vectors {
        let mut output = Vec::new();
        encode::huffman_encode(input.as_bytes(), &mut output);
        assert_eq!(output, hex(expected), "huffman mismatch for {input}");
    }

    let mut output = Vec::new();
    encode::encode_str(b"www.example.com", &mut output);
    assert_eq!(output, hex("8cf1e3c2e5f23a6ba0ab90f4ff"));

    let mut output = Vec::new();
    encode::encode_literal_name_index(1, b"www.example.com", false, &mut output);
    assert_eq!(output, hex("018cf1e3c2e5f23a6ba0ab90f4ff"));
}

#[test]
fn empty_and_literal_boundaries() {
    let mut output = Vec::new();
    encode::encode_str(b"", &mut output);
    assert_eq!(output, vec![0x00]);

    let cases = [
        (14, false, "0e00"),
        (14, true, "1e00"),
        (15, false, "0f0000"),
        (15, true, "1f0000"),
        (16, false, "0f0100"),
        (143, false, "0f800100"),
    ];

    for (index, sensitive, expected) in cases {
        let mut output = Vec::new();
        encode::encode_literal_name_index(index, b"", sensitive, &mut output);
        assert_eq!(output, hex(expected), "literal index {index}");
    }
}

#[test]
fn huffman_table_anchors() {
    assert_eq!(encode::HUFFMAN_TABLE.len(), 257);
    assert_eq!(encode::HUFFMAN_TABLE[0], (13, 0x1ff8));
    assert_eq!(encode::HUFFMAN_TABLE[48], (5, 0x0));
    assert_eq!(encode::HUFFMAN_TABLE[97], (5, 0x3));
    assert_eq!(encode::HUFFMAN_TABLE[256], (30, 0x3fffffff));
}
