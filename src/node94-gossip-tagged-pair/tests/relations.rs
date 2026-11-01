use node94_gossip_tagged_pair::{Budget, Decoded, Failure, ScalarFault, decode_tagged_pair};
#[path = "../examples/support/row_codec.rs"]
mod row_codec;

#[test]
fn unchanged_pre_source_boundary_subset() {
    let input = include_str!("../unit-input.tsv");
    let expected = include_str!("../unit-expected.jsonl");
    assert_eq!(input.lines().count(), 23);
    assert_eq!(expected.lines().count(), 23);
    for (given, wanted) in input.lines().zip(expected.lines()) {
        assert_eq!(row_codec::row(given).unwrap(), wanted);
    }
}

#[test]
fn successive_values_and_selector_limit_failure_keep_state() {
    let wire = [1, 2, 3, 0, 0xfe];
    let mut input = wire.as_slice();
    let mut budget = Budget { mode_word: 1, counter: 0, limit: 17 };
    let first = decode_tagged_pair(&mut input, &mut budget);
    assert_eq!(first.result, Ok(Decoded::TagOne { first: 2, second: 3 }));
    assert_eq!(first.counter_stores.as_slice(), &[1, 9, 17]);
    assert_eq!(input, &wire[3..]);
    let rejected = decode_tagged_pair(&mut input, &mut budget);
    assert_eq!(rejected.result, Err(Failure::Selector(ScalarFault::Budget)));
    assert_eq!(rejected.counter_stores.as_slice(), &[18]);
    assert_eq!(input, &wire[3..]);
    budget.limit = 100;
    assert_eq!(decode_tagged_pair(&mut input, &mut budget).result, Ok(Decoded::TagZero));
    let invalid = decode_tagged_pair(&mut input, &mut budget);
    assert_eq!(invalid.result, Err(Failure::InvalidSelector { found: 254 }));
    assert_eq!(invalid.counter_stores.as_slice(), &[20]);
    assert!(input.is_empty());
}

#[test]
fn second_budget_failure_keeps_first_prefix_but_no_partial_value() {
    let wire = [1, 5, 6, 0];
    let mut input = wire.as_slice();
    let mut budget = Budget { mode_word: 1, counter: 0, limit: 16 };
    let outcome = decode_tagged_pair(&mut input, &mut budget);
    assert_eq!(outcome.result, Err(Failure::Second(ScalarFault::Budget)));
    assert_eq!(outcome.counter_stores.as_slice(), &[1, 9, 17]);
    assert_eq!(budget.counter, 17);
    assert_eq!(input, &[6, 0]);
    budget.limit = 100;
    let next = decode_tagged_pair(&mut input, &mut budget);
    assert_eq!(next.result, Err(Failure::InvalidSelector { found: 6 }));
    assert_eq!(next.counter_stores.as_slice(), &[18]);
    assert_eq!(input, &[0]);
}

#[test]
fn first_error_prevents_the_second_call() {
    let mut input = &[1, 0xfe, 0][..];
    let mut budget = Budget { mode_word: 1, counter: 0, limit: 100 };
    let outcome = decode_tagged_pair(&mut input, &mut budget);
    assert_eq!(outcome.result, Err(Failure::First(ScalarFault::Type { expected: 3, found: 4 })));
    assert_eq!(outcome.counter_stores.as_slice(), &[1, 9]);
    assert_eq!(input, &[0]);
    let next = decode_tagged_pair(&mut input, &mut budget);
    assert_eq!(next.result, Ok(Decoded::TagZero));
    assert_eq!(next.counter_stores.as_slice(), &[10]);
}

#[test]
fn each_scalar_uses_its_current_fast_threshold() {
    for (length, expected, consumed) in [(8, 3, 3), (9, 2, 2)] {
        let mut wire = vec![1, 0];
        wire.extend(std::iter::repeat_n(0xfe, length));
        let mut input = wire.as_slice();
        let mut budget = Budget { mode_word: 1, counter: 0, limit: 17 };
        let result = decode_tagged_pair(&mut input, &mut budget);
        assert_eq!(result.result, Err(Failure::Second(ScalarFault::Type { expected, found: 4 })));
        assert_eq!(result.counter_stores.as_slice(), &[1, 9, 17]);
        assert_eq!(input, &wire[consumed..]);
    }
}

#[test]
fn mode_high_bits_and_fixed_word_cost_ignore_wire_widths() {
    let mut wire = vec![1, 0xfd];
    wire.extend([0xff; 8]);
    wire.push(0xfd);
    wire.extend([0xff; 8]);
    for mode_word in [1, (1_u64 << 32) | 1] {
        let mut input = wire.as_slice();
        let mut budget = Budget { mode_word, counter: 0, limit: 17 };
        let result = decode_tagged_pair(&mut input, &mut budget);
        assert_eq!(result.result, Ok(Decoded::TagOne { first: u64::MAX, second: u64::MAX }));
        assert_eq!(result.counter_stores.as_slice(), &[1, 9, 17]);
        assert!(input.is_empty());
    }
    for mode_word in [0, 2, 1_u64 << 32, u64::MAX] {
        let mut input = wire.as_slice();
        let mut budget = Budget { mode_word, counter: u64::MAX, limit: 0 };
        let result = decode_tagged_pair(&mut input, &mut budget);
        assert!(result.result.is_ok());
        assert!(result.counter_stores.as_slice().is_empty());
        assert_eq!(budget.counter, u64::MAX);
    }
}

#[test]
fn second_truncation_keeps_both_consumed_prefixes() {
    let wire = [1, 0xfb, 0, 1, 0xfd, 0, 1];
    let mut input = wire.as_slice();
    let mut budget = Budget { mode_word: 0, counter: 77, limit: 0 };
    let outcome = decode_tagged_pair(&mut input, &mut budget);
    assert_eq!(outcome.result, Err(Failure::Second(ScalarFault::Need { additional: 6 })));
    assert!(outcome.counter_stores.as_slice().is_empty());
    assert_eq!(input, &wire[5..]);
}
