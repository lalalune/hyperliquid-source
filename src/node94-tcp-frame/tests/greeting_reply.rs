#![cfg(feature = "timed-stream")]

use node94_tcp_frame::greeting::reply::{ErrorKind, HashReply, MapValue, Reply, decode};

fn word(n: u64) -> Vec<u8> {
    if n <= 250 {
        vec![n as u8]
    } else if n <= u16::MAX as u64 {
        [vec![251], (n as u16).to_le_bytes().to_vec()].concat()
    } else if n <= u32::MAX as u64 {
        [vec![252], (n as u32).to_le_bytes().to_vec()].concat()
    } else {
        [vec![253], n.to_le_bytes().to_vec()].concat()
    }
}

fn value(seed: u64, last: u8) -> MapValue {
    MapValue {
        first: [seed, seed + 1, seed + 2, seed + 3],
        second: [seed + 4, seed + 5, seed + 6, seed + 7],
        last,
    }
}

fn map(rows: &[([u8; 20], MapValue)]) -> Vec<u8> {
    let mut out = word(rows.len() as u64);
    for (key, value) in rows {
        out.extend_from_slice(key);
        for n in value.first.iter().chain(value.second.iter()) {
            out.extend(word(*n));
        }
        out.push(value.last);
    }
    out
}

fn prefix(hash: u8) -> Vec<u8> {
    vec![0, 0, 0, hash]
}

fn hash_map(rows: &[([u8; 20], MapValue)]) -> Vec<u8> {
    let mut out = prefix(0);
    out.extend(0..32);
    out.extend(map(rows));
    out
}

fn records(wide: bool) -> Vec<u8> {
    let mut out = prefix(2);
    for record in 0..3 {
        out.extend(word(if wide { u64::MAX - record } else { record }));
        out.extend(word(if wide {
            u32::MAX as u64 + record + 1
        } else {
            record + 5
        }));
        out.extend((0..2048).map(|i| ((i * 17 + record * 41) % 256) as u8));
    }
    out
}

#[test]
fn all_unit_variants_and_nonminimal_tags_preserve_suffix() {
    for tag in 2..=5 {
        let expected = match tag {
            2 => Reply::Variant2,
            3 => Reply::Variant3,
            4 => Reply::Variant4,
            _ => Reply::Variant5,
        };
        for bytes in [vec![tag], vec![251, tag, 0], vec![252, tag, 0, 0, 0]] {
            let mut input = bytes.clone();
            input.extend([77, 88]);
            let got = decode(&input, 4).unwrap();
            assert_eq!(got.reply, expected);
            assert_eq!(
                (got.consumed, got.remaining, got.charged),
                (bytes.len(), 2, 4)
            );
        }
    }
}

#[test]
fn all_scalar_width_combinations_and_high_bits_remain_in_wire_order() {
    let values = [
        0,
        250,
        251,
        65535,
        65536,
        u32::MAX as u64,
        1 << 63,
        u64::MAX,
    ];
    for a in values {
        for b in values {
            for c in values {
                let mut input = vec![1];
                for n in [a, b, c] {
                    input.extend(word(n));
                }
                let len = input.len();
                input.push(0xaa);
                let got = decode(&input, 28).unwrap();
                assert_eq!(got.reply, Reply::Variant1([a, b, c]));
                assert_eq!((got.consumed, got.remaining, got.charged), (len, 1, 28));
            }
        }
    }
}

#[test]
fn outer_tag_bounds_and_fast_slow_integer_errors() {
    for tag in [6, 250] {
        let got = decode(&[tag], 1000).unwrap_err();
        assert_eq!(
            got.kind,
            ErrorKind::UnexpectedVariant {
                type_name: "AbciStreamGreeting",
                found: tag as u32,
                max: 5
            }
        );
        assert_eq!((got.consumed, got.charged), (1, 4));
    }
    for marker in [253, 254, 255] {
        for len in [1, 5] {
            let mut input = vec![0; len];
            input[0] = marker;
            let got = decode(&input, 1000).unwrap_err();
            assert_eq!(
                got.kind,
                ErrorKind::InvalidIntegerType {
                    expected: 2,
                    found: match marker {
                        253 => 3,
                        254 => 4,
                        _ => 12,
                    }
                }
            );
            assert_eq!(got.consumed, if len > 4 { 0 } else { 1 });
        }
    }
}

#[test]
fn budget_precedes_input_and_failure_keeps_increment() {
    let got = decode(&[], 3).unwrap_err();
    assert_eq!(got.kind, ErrorKind::Limit);
    assert_eq!((got.consumed, got.charged), (0, 4));
    let got = decode(&[1, 0, 0, 0], 11).unwrap_err();
    assert_eq!(got.kind, ErrorKind::Limit);
    assert_eq!((got.consumed, got.charged), (1, 12));
}

#[test]
fn scalar_shortage_consumes_marker_only() {
    let got = decode(&[1, 252, 0x77], 1000).unwrap_err();
    assert_eq!(got.kind, ErrorKind::UnexpectedEnd { needed: 3 });
    assert_eq!((got.consumed, got.charged), (2, 12));
    let got = decode(&[252, 1, 0], 1000).unwrap_err();
    assert_eq!(got.kind, ErrorKind::UnexpectedEnd { needed: 2 });
    assert_eq!((got.consumed, got.charged), (1, 4));
}

#[test]
fn u64_and_kind5_errors_use_distinct_expected_codes() {
    for marker in [254, 255] {
        for fast in [false, true] {
            let mut ordinary = vec![1, marker];
            if fast {
                ordinary.extend([0; 8]);
            }
            let got = decode(&ordinary, u64::MAX).unwrap_err();
            assert_eq!(
                got.kind,
                ErrorKind::InvalidIntegerType {
                    expected: if fast { 2 } else { 3 },
                    found: if marker == 254 { 4 } else { 12 }
                }
            );
            assert_eq!((got.consumed, got.charged), (if fast { 1 } else { 2 }, 12));
            let mut special = prefix(2);
            special.push(marker);
            if fast {
                special.extend([0; 8]);
            }
            let got = decode(&special, u64::MAX).unwrap_err();
            assert_eq!(
                got.kind,
                ErrorKind::InvalidIntegerType {
                    expected: 5,
                    found: if marker == 254 { 4 } else { 12 }
                }
            );
            assert_eq!((got.consumed, got.charged), (if fast { 4 } else { 5 }, 32));
        }
    }
}

#[test]
fn byte_vector_checks_charge_and_length_before_copy() {
    let got = decode(&[0, 3, 0xaa], 1000).unwrap_err();
    assert_eq!(got.kind, ErrorKind::CollectionTooLong);
    assert_eq!((got.consumed, got.charged), (2, 15));
    let mut input = vec![0];
    input.extend(word(u64::MAX));
    let got = decode(&input, u64::MAX).unwrap_err();
    assert_eq!(got.kind, ErrorKind::Limit);
    assert_eq!((got.consumed, got.charged), (10, 12));
    let mut input = vec![0];
    input.extend(word(257));
    input.extend((0..257).map(|i| i as u8));
    input.extend([42, 0]);
    input.extend([0; 32]);
    input.push(0);
    let got = decode(&input, 1000).unwrap();
    match got.reply {
        Reply::Variant0 { bytes, word, .. } => {
            assert_eq!(word, 42);
            assert_eq!(bytes, (0..257).map(|i| i as u8).collect::<Vec<_>>());
        }
        _ => panic!("wrong reply"),
    }
    assert_eq!(got.charged, 321);
}

#[test]
fn hash_variants_zero_and_one_keep_bytes_and_maps_separate() {
    let rows = [([7; 20], value(1, 200))];
    let got = decode(&hash_map(&rows), 1000).unwrap();
    match got.reply {
        Reply::Variant0 {
            hash: HashReply::Variant0 { bytes, map },
            ..
        } => {
            assert_eq!(bytes, core::array::from_fn(|i| i as u8));
            assert_eq!(map[&[7; 20]], value(1, 200));
        }
        _ => panic!("wrong hash"),
    }
    assert_eq!(got.charged, 149);
    let mut input = prefix(1);
    input.extend([0xa5; 32]);
    input.extend(map(&rows));
    input.extend(map(&[([8; 20], value(10, 255))]));
    let got = decode(&input, 1000).unwrap();
    match got.reply {
        Reply::Variant0 {
            hash:
                HashReply::Variant1 {
                    bytes,
                    first,
                    second,
                },
            ..
        } => {
            assert_eq!(bytes, [0xa5; 32]);
            assert_eq!(first[&[7; 20]], value(1, 200));
            assert_eq!(second[&[8; 20]], value(10, 255));
        }
        _ => panic!("wrong hash"),
    }
    assert_eq!(got.charged, 242);
}

#[test]
fn maps_accept_large_inputs_and_last_duplicate_wins_in_lexicographic_order() {
    let rows: Vec<_> = (0..40)
        .rev()
        .map(|i| {
            let mut key = [0; 20];
            key[0] = (i % 20) as u8;
            key[19] = ((i % 20) ^ 0x80) as u8;
            (key, value(i, i as u8))
        })
        .collect();
    let got = decode(&hash_map(&rows), 10_000).unwrap();
    match got.reply {
        Reply::Variant0 {
            hash: HashReply::Variant0 { map, .. },
            ..
        } => {
            assert_eq!(map.len(), 20);
            for (index, (key, got)) in map.iter().enumerate() {
                assert_eq!(key[0] as usize, index);
                assert_eq!(*got, value(index as u64, index as u8));
            }
        }
        _ => panic!("wrong hash"),
    }
    assert_eq!(got.charged, 64 + 85 * 40);
}

#[test]
fn map_admission_reserves_attempts_before_rows_not_distinct_keys() {
    let rows = vec![([0; 20], value(0, 0)); 10];
    let got = decode(&hash_map(&rows), 1000).unwrap_err();
    assert_eq!(got.kind, ErrorKind::Limit);
    assert_eq!((got.consumed, got.charged), (37, 1024));
    let got = decode(&hash_map(&rows[..9]), 1000).unwrap();
    assert_eq!(got.charged, 829);
    match got.reply {
        Reply::Variant0 {
            hash: HashReply::Variant0 { map, .. },
            ..
        } => assert_eq!(map.len(), 1),
        _ => panic!("wrong hash"),
    }
}

#[test]
fn map_count_overflow_retains_charge_before_reservation() {
    let mut input = prefix(0);
    input.extend([0; 32]);
    input.extend(word(u64::MAX));
    let got = decode(&input, u64::MAX).unwrap_err();
    assert_eq!(got.kind, ErrorKind::Limit);
    assert_eq!((got.consumed, got.charged), (45, 64));

    // Multiplication fits, but adding the already-consumed greeting prefix does not.
    let mut input = prefix(0);
    input.extend([0; 32]);
    input.extend(word((u64::MAX - 8) / 96));
    let got = decode(&input, u64::MAX).unwrap_err();
    assert_eq!(got.kind, ErrorKind::Limit);
    assert_eq!((got.consumed, got.charged), (45, 64));
}

#[test]
fn map_key_and_value_failures_retain_refund_and_reached_charges() {
    let mut input = prefix(0);
    input.extend([0; 32]);
    input.push(1);
    input.extend([0; 3]);
    let got = decode(&input, 1000).unwrap_err();
    assert_eq!(got.kind, ErrorKind::UnexpectedEnd { needed: 17 });
    assert_eq!((got.consumed, got.charged), (37, 84));
    input.truncate(37);
    input.extend([0; 20]);
    input.extend([1, 2, 3]);
    let got = decode(&input, 1000).unwrap_err();
    assert_eq!(got.kind, ErrorKind::UnexpectedEnd { needed: 1 });
    assert_eq!((got.consumed, got.charged), (60, 116));
}

#[test]
fn records_preserve_all_6144_array_bytes_and_six_word_values() {
    for wide in [false, true] {
        let mut input = records(wide);
        let len = input.len();
        input.extend([42, 43]);
        let got = decode(&input, 6216).unwrap();
        assert_eq!((got.consumed, got.remaining, got.charged), (len, 2, 6216));
        match got.reply {
            Reply::Variant0 {
                hash: HashReply::Variant2(records),
                ..
            } => {
                for (index, record) in records.iter().enumerate() {
                    assert_eq!(
                        record.first,
                        if wide {
                            u64::MAX - index as u64
                        } else {
                            index as u64
                        }
                    );
                    assert_eq!(
                        record.second,
                        if wide {
                            u32::MAX as u64 + index as u64 + 1
                        } else {
                            index as u64 + 5
                        }
                    );
                    for (offset, byte) in record.bytes.iter().enumerate() {
                        assert_eq!(
                            *byte,
                            ((offset * 17 + index * 41) % 256) as u8,
                            "record {index} byte {offset}"
                        );
                    }
                }
            }
            _ => panic!("wrong hash"),
        }
    }
}

#[test]
fn small_limit_rejects_first_record_array_before_reading_it() {
    let input = records(false);
    let got = decode(&input, 1000).unwrap_err();
    assert_eq!(got.kind, ErrorKind::Limit);
    assert_eq!((got.consumed, got.charged), (6, 2088));
    let got = decode(&input[..10], 6216).unwrap_err();
    assert_eq!(got.kind, ErrorKind::UnexpectedEnd { needed: 2044 });
    assert_eq!((got.consumed, got.charged), (6, 2088));
}

#[test]
fn each_nested_selector_is_range_checked() {
    let got = decode(&prefix(3), 1000).unwrap_err();
    assert_eq!(
        got.kind,
        ErrorKind::UnexpectedVariant {
            type_name: "GreetingHash",
            found: 3,
            max: 2
        }
    );
    assert_eq!((got.consumed, got.charged), (4, 24));
}

#[test]
fn every_cut_of_complex_replies_returns_an_error_with_bounded_cursor() {
    let fixtures = [records(true), hash_map(&[([1; 20], value(65536, 255))])];
    for input in fixtures {
        for cut in 0..input.len() {
            let failure = decode(&input[..cut], u64::MAX).unwrap_err();
            assert!(failure.consumed <= cut);
        }
        assert!(decode(&input, u64::MAX).is_ok());
    }
}

#[test]
fn arbitrary_bounded_inputs_do_not_panic() {
    let mut state = 0x94_u64;
    for len in 0..96 {
        for _ in 0..30 {
            let input: Vec<_> = (0..len)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    state as u8
                })
                .collect();
            let result = decode(&input, 10_000);
            if let Err(failure) = result {
                assert!(failure.consumed <= input.len());
            }
        }
    }
}

#[test]
fn fourth_word_in_each_block_keeps_fast_and_slow_error_context() {
    for prior_words in [3, 7] {
        for fast in [false, true] {
            let mut input = prefix(0);
            input.extend([0; 32]);
            input.push(1);
            input.extend([0; 20]);
            input.extend(vec![0; prior_words]);
            input.push(254);
            if fast {
                input.extend([0; 8]);
            }
            let got = decode(&input, 1000).unwrap_err();
            assert_eq!(
                got.kind,
                ErrorKind::InvalidIntegerType {
                    expected: if fast { 2 } else { 3 },
                    found: 4
                }
            );
            assert_eq!(got.consumed, 57 + prior_words + usize::from(!fast));
            assert_eq!(got.charged, if prior_words == 3 { 116 } else { 148 });
        }
    }
}
