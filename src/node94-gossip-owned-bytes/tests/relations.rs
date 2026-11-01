use node94_gossip_owned_bytes::{
    Budget, Failure, HeaderFault, Utf8Fault, decode_owned_bytes,
};

#[path = "../examples/support/row_codec.rs"]
mod row_codec;

#[test]
fn unchanged_pre_source_validator_subset() {
    let input = include_str!("../unit-validator-input.tsv");
    let expected = include_str!("../unit-validator-expected.jsonl");
    assert_eq!(input.lines().count(), 25);
    assert_eq!(expected.lines().count(), 25);
    for (given, wanted) in input.lines().zip(expected.lines()) {
        assert_eq!(row_codec::validator_row(given).unwrap(), wanted);
    }
}

#[test]
fn unchanged_pre_source_wire_subset() {
    let input = include_str!("../unit-wire-input.tsv");
    let expected = include_str!("../unit-wire-expected.jsonl");
    assert_eq!(input.lines().count(), 19);
    assert_eq!(expected.lines().count(), 19);
    for (given, wanted) in input.lines().zip(expected.lines()) {
        assert_eq!(row_codec::wire_row(given).unwrap(), wanted);
    }
}

#[test]
fn successive_success_invalid_and_empty_values_keep_charges_and_suffixes() {
    let wire = [2, 0xc2, 0x80, 1, 0xff, 0, 0xde, 0xad];
    let mut input = wire.as_slice();
    let mut budget = Budget { mode_word: 1, counter: 0, limit: 30 };
    let first = decode_owned_bytes(&mut input, &mut budget);
    assert_eq!(first.counter_stores.as_slice(), &[8, 10]);
    assert_eq!(first.result.unwrap().as_bytes(), &[0xc2, 0x80]);
    assert_eq!(input, &wire[3..]);
    let second = decode_owned_bytes(&mut input, &mut budget);
    assert_eq!(second.counter_stores.as_slice(), &[18, 19]);
    assert_eq!(second.result, Err(Failure::InvalidUtf8(Utf8Fault { valid_up_to: 0, error_len: Some(1) })));
    assert_eq!(second.release_request_length, Some(1));
    assert_eq!(input, &wire[5..]);
    let third = decode_owned_bytes(&mut input, &mut budget);
    assert_eq!(third.counter_stores.as_slice(), &[27, 27]);
    assert!(third.result.unwrap().as_bytes().is_empty());
    assert_eq!(input.as_ptr(), wire[6..].as_ptr());
    let fourth = decode_owned_bytes(&mut input, &mut budget);
    assert_eq!(fourth.result, Err(Failure::Header(HeaderFault::Budget)));
    assert_eq!(fourth.counter_stores.as_slice(), &[35]);
    assert_eq!(input, &wire[6..]);
}

#[test]
fn full_mode_and_low_dword_modes_differ_even_for_zero_length() {
    for mode_word in [2, 1_u64 << 32] {
        let mut input = &[0][..];
        let mut budget = Budget { mode_word, counter: 5, limit: 4 };
        let result = decode_owned_bytes(&mut input, &mut budget);
        assert_eq!(result.result, Err(Failure::PayloadBudget));
        assert_eq!(result.counter_stores.as_slice(), &[5]);
        assert_eq!(budget.counter, 5);
        assert!(input.is_empty());
    }
    let mut input = &[0][..];
    let mut budget = Budget { mode_word: (1_u64 << 32) | 1, counter: 0, limit: 8 };
    let result = decode_owned_bytes(&mut input, &mut budget);
    assert!(result.result.unwrap().as_bytes().is_empty());
    assert_eq!(result.counter_stores.as_slice(), &[8, 8]);
}

#[test]
fn real_header_dependency_retains_fast_and_slow_error_cursor_difference() {
    let long = [0xfe; 9];
    for (wire, expected, remaining) in [(&long[..1], 3, 0), (&long[..], 2, 9)] {
        let mut input = wire;
        let mut budget = Budget { mode_word: 0, counter: u64::MAX, limit: 0 };
        let result = decode_owned_bytes(&mut input, &mut budget);
        assert_eq!(result.result, Err(Failure::Header(HeaderFault::Type { expected, found: 4 })));
        assert!(result.counter_stores.as_slice().is_empty());
        assert_eq!(input.len(), remaining);
    }
}

#[test]
fn counter_overflow_precedes_availability_and_owned_bytes_outlive_input() {
    let mut input = &[][..];
    let mut budget = Budget { mode_word: 1, counter: u64::MAX - 7, limit: u64::MAX };
    let rejected = decode_owned_bytes(&mut input, &mut budget);
    assert_eq!(rejected.result, Err(Failure::Header(HeaderFault::Budget)));
    assert!(rejected.counter_stores.as_slice().is_empty());
    let owned;
    {
        let wire = vec![2, 0xc2, 0x80];
        let mut input = wire.as_slice();
        let mut budget = Budget { mode_word: 0, counter: u64::MAX, limit: 0 };
        owned = decode_owned_bytes(&mut input, &mut budget).result.unwrap();
        assert!(input.is_empty());
        assert_ne!(owned.as_bytes().as_ptr(), wire[1..].as_ptr());
    }
    assert_eq!(owned.into_bytes(), [0xc2, 0x80]);
}

#[test]
fn unavailable_payload_preserves_bytes_for_the_next_header() {
    let wire = [3, 0xff, 0];
    let mut input = wire.as_slice();
    let mut budget = Budget { mode_word: 1, counter: 0, limit: 100 };
    let first = decode_owned_bytes(&mut input, &mut budget);
    assert_eq!(first.result, Err(Failure::PayloadUnavailable));
    assert_eq!(first.counter_stores.as_slice(), &[8, 11]);
    assert_eq!(first.release_request_length, None);
    assert_eq!(input, &[0xff, 0]);
    let second = decode_owned_bytes(&mut input, &mut budget);
    assert_eq!(second.result, Err(Failure::Header(HeaderFault::Type { expected: 3, found: 12 })));
    assert_eq!(second.counter_stores.as_slice(), &[19]);
    assert_eq!(input, &[0]);
    let third = decode_owned_bytes(&mut input, &mut budget);
    assert_eq!(third.counter_stores.as_slice(), &[27, 27]);
    assert!(third.result.unwrap().as_bytes().is_empty());
    assert!(input.is_empty());
}
