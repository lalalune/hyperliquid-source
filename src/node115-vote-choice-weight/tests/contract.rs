use node115_vote_choice_weight::encode;

#[test]
fn exact_fields_and_integer_boundaries() {
    assert_eq!(encode(0, 0, 127).as_slice(), b"\x92\xa3yes\x7f");
    assert_eq!(
        encode(1, 1, 128).as_slice(),
        b"\x82\xa6choice\xa2no\xa6weight\xcc\x80"
    );
    assert_eq!(encode(0, 2, 256).as_slice(), b"\x92\xa7abstain\xcd\x01\x00");
    assert_eq!(
        encode(2, 3, 65536).as_slice(),
        b"\xb2\xa6choice\xa7abstain\xce\x00\x01\x00\x00"
    );
    assert_eq!(
        encode(1, 255, u64::MAX).as_slice(),
        b"\x82\xa6choice\xa7abstain\xa6weight\xcf\xff\xff\xff\xff\xff\xff\xff\xff"
    );
}

#[test]
fn all_raw_choices_match_observed_fallback() {
    for mode in 0..=u8::MAX {
        let fallback = encode(mode, 2, 123);
        for choice in 2..=u8::MAX {
            assert_eq!(encode(mode, choice, 123), fallback);
        }
    }
}

#[test]
fn independent_struct_pack_fixtures() {
    let mut count = 0;
    for line in include_str!("reference-vectors.txt")
        .lines()
        .filter(|x| !x.starts_with('#'))
    {
        let columns: Vec<_> = line.split_whitespace().collect();
        let mode = columns[0].parse().unwrap();
        let choice = columns[1].parse().unwrap();
        let weight = columns[2].parse().unwrap();
        let expected: Vec<_> = columns[3]
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        assert_eq!(
            encode(mode, choice, weight).as_slice(),
            expected,
            "case {count}"
        );
        count += 1;
    }
    assert_eq!(count, 7680);
}
