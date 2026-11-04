use node115_fee_rate_map_codec::encode_bits;

#[test]
fn matches_frozen_binary_bound_bit_patterns() {
    let corpus =
        include_str!("../../../research/work-items/RE-005-node115-fee-rate-map-wire/vectors.tsv");
    for row in corpus.lines().skip(1) {
        let fields: Vec<_> = row.split('\t').collect();
        let words = core::array::from_fn(|i| u64::from_str_radix(fields[i + 1], 16).unwrap());
        let actual: String = encode_bits(words)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(actual, fields[5], "{}", fields[0]);
    }
}
