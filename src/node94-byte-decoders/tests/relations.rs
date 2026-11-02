use hyperliquid_node94_byte_decoders::{Budget, DecodeError, read_bool, read_u8};

#[test]
fn u8_values_above_the_varint_marker_are_plain_bytes() {
    let mut input = &[251, 252, 253, 254, 255][..];
    let mut budget = Budget { mode_word: 3, counter: u64::MAX, limit: 0 };
    for value in 251..=255 {
        assert_eq!(read_u8(&mut input, &mut budget), Ok(value));
    }
    assert!(input.is_empty());
    assert_eq!(budget.counter, u64::MAX);
}

#[test]
fn invalid_boolean_is_consumed_before_the_following_read() {
    let mut input = &[2, 1, 0][..];
    let mut budget = Budget { mode_word: 1, counter: 0, limit: 3 };
    assert_eq!(read_bool(&mut input, &mut budget), Err(DecodeError::InvalidBooleanByte { found: 2 }));
    assert_eq!(input, &[1, 0]);
    assert_eq!(budget.counter, 1);
    assert_eq!(read_bool(&mut input, &mut budget), Ok(true));
    assert_eq!(read_bool(&mut input, &mut budget), Ok(false));
    assert_eq!(budget.counter, 3);
}

#[test]
fn empty_and_limit_failures_retain_prior_charge_in_source_order() {
    let mut input = &[][..];
    let mut budget = Budget { mode_word: 1, counter: 0, limit: 1 };
    assert_eq!(read_u8(&mut input, &mut budget), Err(DecodeError::UnexpectedEnd { needed: 1 }));
    assert_eq!(budget.counter, 1);
    assert_eq!(read_u8(&mut input, &mut budget), Err(DecodeError::BudgetExceeded { word8_write: None }));
    assert_eq!(budget.counter, 2);
    assert_eq!(read_bool(&mut input, &mut budget), Err(DecodeError::BudgetExceeded { word8_write: Some(1) }));
    assert_eq!(budget.counter, 3);
}

#[test]
fn equality_at_the_maximum_counter_then_overflow_preserves_the_suffix() {
    let bytes = [0, 1];
    let mut input = bytes.as_slice();
    let mut budget = Budget { mode_word: 1, counter: u64::MAX - 1, limit: u64::MAX };
    assert_eq!(read_bool(&mut input, &mut budget), Ok(false));
    assert_eq!(budget.counter, u64::MAX);
    assert_eq!(input.as_ptr(), bytes[1..].as_ptr());
    assert_eq!(read_bool(&mut input, &mut budget), Err(DecodeError::BudgetExceeded { word8_write: Some(1) }));
    assert_eq!(budget.counter, u64::MAX);
    assert_eq!(input, &[1]);
    assert_eq!(read_u8(&mut input, &mut budget), Err(DecodeError::BudgetExceeded { word8_write: None }));
    assert_eq!(input.as_ptr(), bytes[1..].as_ptr());
}
