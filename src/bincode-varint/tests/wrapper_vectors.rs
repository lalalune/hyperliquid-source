use hl_bincode_varint::{ReaderError, SliceDecoder, SliceError};

#[path = "../../../research/work-items/RE-005-bincode-wrapper-state-94/protocol.rs"]
mod protocol;

#[test]
fn frozen_wrapper_state_and_request_composition() {
    let inputs =
        include_str!("../../../research/work-items/RE-005-bincode-wrapper-state-94/inputs.tsv");
    let expected =
        include_str!("../../../research/work-items/RE-005-bincode-wrapper-state-94/expected.tsv");
    assert_eq!(inputs.lines().count(), 4726);
    assert_eq!(inputs.lines().count(), expected.lines().count());
    for (input, expected) in inputs.lines().zip(expected.lines()) {
        assert_eq!(protocol::run(input), expected);
    }
}

#[test]
fn charge_failure_precedes_empty_input_and_retains_limit_increment() {
    let mut decoder = SliceDecoder::from_state(&[], 1, 3, 0);
    assert_eq!(decoder.read_u32(), Err(SliceError::LimitExceeded));
    assert_eq!(decoder.charge(), 4);
    assert_eq!(decoder.read_u32(), Err(SliceError::LimitExceeded));
    assert_eq!(decoder.charge(), 8);
    assert!(decoder.remaining().is_empty());
}

#[test]
fn overflow_preserves_charge_while_exact_maximum_can_succeed() {
    let mut rejected = SliceDecoder::from_state(&[1], 1, u64::MAX, u64::MAX - 3);
    assert_eq!(rejected.read_u32(), Err(SliceError::LimitExceeded));
    assert_eq!(rejected.charge(), u64::MAX - 3);
    assert_eq!(rejected.remaining(), &[1]);
    let mut accepted = SliceDecoder::from_state(&[1], 1, u64::MAX, u64::MAX - 4);
    assert_eq!(accepted.read_u32(), Ok(1));
    assert_eq!(accepted.charge(), u64::MAX);
    assert!(accepted.remaining().is_empty());
}

#[test]
fn same_marker_changes_error_and_consumption_at_u64_threshold() {
    let short = [0xfe; 8];
    let long = [0xfe; 9];
    let mut slow = SliceDecoder::from_state(&short, 1, 100, 0);
    let mut fast = SliceDecoder::from_state(&long, 1, 100, 0);
    assert_eq!(
        slow.read_u64(),
        Err(SliceError::Reader(ReaderError::InvalidIntegerType {
            expected_code: 3,
            found_code: 4,
        }))
    );
    assert_eq!(
        fast.read_u64(),
        Err(SliceError::Reader(ReaderError::InvalidIntegerType {
            expected_code: 2,
            found_code: 4,
        }))
    );
    assert_eq!(slow.remaining(), &short[1..]);
    assert_eq!(fast.remaining(), &long);
    assert_eq!((slow.charge(), fast.charge()), (8, 8));
}
