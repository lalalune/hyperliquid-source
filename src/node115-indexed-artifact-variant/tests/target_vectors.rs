use node115_indexed_artifact_variant::IndexedArtifactVariant;

const IDENT_CASES: &str = include_str!(
    "../../../research/work-items/RE-009-indexed-artifact-content-codec-115/ident-cases.tsv"
);

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
fn all_target_identifier_rows_match_exact_name_indexing() {
    let mut rows = 0usize;
    for line in IDENT_CASES.lines().skip(1) {
        let cols: Vec<_> = line.split('\t').collect();
        assert_eq!(cols.len(), 6, "malformed fixture row: {line}");
        let input = parse_hex(cols[1]);
        let value = core::str::from_utf8(&input)
            .ok()
            .and_then(IndexedArtifactVariant::from_name);

        if let Some(variant) = value {
            assert_eq!(cols[3], "ok");
            assert_eq!(cols[4].parse::<u8>().unwrap(), variant.index());
        } else {
            assert_eq!(cols[3], "err");
        }
        assert_eq!(cols[5], "match");
        rows += 1;
    }
    assert_eq!(rows, 862);
}

#[test]
fn declaration_order_and_exact_spellings_are_stable() {
    for (index, variant) in IndexedArtifactVariant::ALL.into_iter().enumerate() {
        assert_eq!(variant.index(), index as u8);
        assert_eq!(
            IndexedArtifactVariant::from_name(variant.name()),
            Some(variant)
        );
    }
    assert_eq!(IndexedArtifactVariant::from_name("nodemetadata"), None);
    assert_eq!(
        IndexedArtifactVariant::from_name("PublisherBinaryMetadataExtra"),
        None
    );
}
