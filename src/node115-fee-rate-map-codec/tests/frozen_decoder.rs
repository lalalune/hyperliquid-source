use node115_fee_rate_map_codec::{
    decode_prefix, CacheState, ContainerKind, DecodeError, DecodeOutcome,
};

fn bytes(hex: &str) -> Vec<u8> {
    if hex == "-" {
        return Vec::new();
    }
    assert_eq!(hex.len() % 2, 0);
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

fn check(corpus: &str, expected_rows: usize) {
    let mut count = 0;
    for row in corpus.lines().skip(1) {
        let fields: Vec<_> = row.split('\t').collect();
        assert_eq!(fields.len(), 10);
        let input = bytes(fields[1]);
        let actual = decode_prefix(&input, fields[2].parse().unwrap());
        let parameter = || fields[6].parse::<u8>().unwrap();
        let expected = match fields[5] {
            "Value" => {
                let words: Vec<_> = fields[7]
                    .split(',')
                    .map(|word| u64::from_str_radix(word, 16).unwrap())
                    .collect();
                DecodeOutcome::Value(words.try_into().unwrap())
            }
            "PanicBoundary" => DecodeOutcome::PanicBoundary(match fields[6] {
                "Array" => ContainerKind::Array,
                "Map" => ContainerKind::Map,
                "Extension" => ContainerKind::Extension,
                other => panic!("unknown container {other}"),
            }),
            error => DecodeOutcome::Error(match error {
                "MarkerEof" => DecodeError::MarkerEof,
                "TruncatedRead" => DecodeError::TruncatedRead,
                "PayloadTooShort" => DecodeError::PayloadTooShort,
                "UnexpectedMarker" => DecodeError::UnexpectedMarker(parameter()),
                "InvalidLength" => DecodeError::InvalidLength(parameter()),
                "ExcessElements" => DecodeError::ExcessElements,
                "InvalidType" => DecodeError::InvalidType,
                "InvalidUtf8" => DecodeError::InvalidUtf8,
                "DepthLimit" => DecodeError::DepthLimit,
                other => panic!("unknown error {other}"),
            }),
        };
        assert_eq!(actual.outcome, expected, "{}: {}", fields[0], fields[9]);
        assert_eq!(
            actual.consumed,
            fields[3].parse::<usize>().unwrap(),
            "{} cursor",
            fields[0]
        );
        assert_eq!(
            actual.depth_after,
            fields[4].parse::<u16>().unwrap(),
            "{} depth",
            fields[0]
        );
        assert_eq!(actual.cache, CacheState::Fresh, "{} cache", fields[0]);
        count += 1;
    }
    assert_eq!(count, expected_rows);
}

#[test]
fn matches_independent_pre_source_marker_and_state_cases() {
    check(
        include_str!(
            "../../../research/work-items/RE-005-node115-fee-rate-map-decode/manual-cases.tsv"
        ),
        925,
    );
}

#[test]
fn matches_independent_pre_source_scalar_witnesses() {
    check(
        include_str!(
            "../../../research/work-items/RE-005-node115-fee-rate-map-decode/scalar-cases.tsv"
        ),
        62,
    );
}
