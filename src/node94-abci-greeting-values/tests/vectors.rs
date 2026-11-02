//! Fixed grammar/state expectations derived before source from the native proof.
//! Helpers construct input bytes only; no production encoder supplies expectations.

use node94_abci_greeting_values::{
    Error, Greeting, NativeError, Reader, Signature, StateError, decode_with_limit,
};

fn native(error: NativeError) -> Error {
    Error::Native(error)
}

fn read(
    data: &[u8],
    limit: Option<u64>,
    charged: u64,
) -> (Result<Greeting, Error>, usize, usize, u64) {
    let mut reader = Reader::new(data, 0, limit, charged).unwrap();
    let result = reader.decode();
    (
        result,
        reader.cursor(),
        reader.remaining(),
        reader.charged(),
    )
}

fn map_prefix(inner: u8) -> Vec<u8> {
    let mut bytes = vec![0, 0, 0, inner];
    bytes.extend_from_slice(&[0; 32]);
    bytes
}

fn row(bytes: &mut Vec<u8>, key: [u8; 20], limb: u8, recovery: u8) {
    assert!(limb <= 250);
    bytes.extend_from_slice(&key);
    bytes.extend_from_slice(&[limb; 8]);
    bytes.push(recovery);
}

#[test]
fn all_empty_tags_consume_only_the_tag() {
    for (tag, expected) in [
        (2, Greeting::Empty2),
        (3, Greeting::Empty3),
        (4, Greeting::Empty4),
        (5, Greeting::Empty5),
    ] {
        assert_eq!(read(&[tag, 99], Some(4), 0), (Ok(expected), 1, 1, 4));
    }
}

#[test]
fn u64_error_threshold_changes_code_and_marker_consumption() {
    let mut short = vec![1, 254];
    short.extend_from_slice(&[0; 7]);
    assert_eq!(
        read(&short, Some(100), 0),
        (
            Err(native(NativeError::InvalidIntegerType {
                expected: 3,
                found: 4
            })),
            2,
            7,
            12
        )
    );
    short.push(0);
    assert_eq!(
        read(&short, Some(100), 0),
        (
            Err(native(NativeError::InvalidIntegerType {
                expected: 2,
                found: 4
            })),
            1,
            9,
            12
        )
    );
}

#[test]
fn u32_fast_and_slow_rejection_keep_distinct_cursors() {
    assert_eq!(
        read(&[253], None, 9),
        (
            Err(native(NativeError::InvalidIntegerType {
                expected: 2,
                found: 3
            })),
            1,
            0,
            9
        )
    );
    assert_eq!(
        read(&[253, 1, 2, 3, 4], None, 9),
        (
            Err(native(NativeError::InvalidIntegerType {
                expected: 2,
                found: 3
            })),
            0,
            5,
            9
        )
    );
}

#[test]
fn short_payload_retains_payload_and_charge() {
    assert_eq!(
        read(&[1, 253, 7, 8], Some(100), 0),
        (
            Err(native(NativeError::UnexpectedEnd { needed: 6 })),
            2,
            2,
            12
        )
    );
    assert_eq!(
        read(&[], Some(100), 0),
        (
            Err(native(NativeError::UnexpectedEnd { needed: 1 })),
            0,
            0,
            4
        )
    );
}

#[test]
fn finite_over_limit_charge_is_stored_but_overflow_is_not() {
    assert_eq!(
        read(&[2], Some(10), 7),
        (Err(native(NativeError::LimitExceeded)), 0, 1, 11)
    );
    assert_eq!(
        read(&[2], Some(u64::MAX), u64::MAX - 3),
        (Err(native(NativeError::LimitExceeded)), 0, 1, u64::MAX - 3)
    );
    assert_eq!(
        read(&[2], None, u64::MAX),
        (Ok(Greeting::Empty2), 1, 0, u64::MAX)
    );
}

#[test]
fn bulk_shortage_has_kind_one_and_does_not_consume_payload() {
    assert_eq!(
        read(&[0, 3, b'a', b'b'], Some(100), 0),
        (Err(native(NativeError::BulkUnexpectedEnd)), 2, 2, 15)
    );
}

#[test]
fn group_eof_keeps_the_accepted_group_reservation() {
    let mut wire = map_prefix(0);
    wire.push(1);
    wire.extend_from_slice(&[0; 20]);
    // Header/length charge64; reserve96/refund96; key20; group32.
    assert_eq!(
        read(&wire, Some(u64::MAX), 0),
        (
            Err(native(NativeError::UnexpectedEnd { needed: 1 })),
            57,
            0,
            116
        )
    );
}

#[test]
fn unfinished_map_rows_keep_their_reservation() {
    let mut wire = map_prefix(0);
    wire.push(3);
    // Header64 + reserve288 - first refund96 + attempted key20 =276.
    assert_eq!(
        read(&wire, Some(u64::MAX), 0),
        (
            Err(native(NativeError::UnexpectedEnd { needed: 20 })),
            37,
            0,
            276
        )
    );
}

#[test]
fn duplicate_last_wins_and_unsigned_keys_remain_ordered() {
    let mut wire = map_prefix(0);
    wire.push(3);
    row(&mut wire, [128; 20], 1, 2);
    row(&mut wire, [127; 20], 3, 4);
    row(&mut wire, [128; 20], 9, 255);
    let (result, cursor, remaining, charged) = read(&wire, Some(u64::MAX), 0);
    let Greeting::Data0 {
        bytes,
        scalar,
        hash,
        signatures,
    } = result.unwrap()
    else {
        panic!("expected Data0")
    };
    assert_eq!(bytes, Vec::<u8>::new());
    assert_eq!(scalar, 0);
    assert_eq!(hash, [0; 32]);
    assert_eq!(
        signatures.into_iter().collect::<Vec<_>>(),
        vec![
            (
                [127; 20],
                Signature {
                    limbs: [3; 8],
                    recovery: 4
                }
            ),
            (
                [128; 20],
                Signature {
                    limbs: [9; 8],
                    recovery: 255
                }
            ),
        ]
    );
    assert_eq!((cursor, remaining, charged), (wire.len(), 0, 319));
}

#[test]
fn second_map_error_retains_state_after_the_first_map() {
    let mut wire = map_prefix(1);
    wire.push(1);
    row(&mut wire, [1; 20], 2, 3);
    wire.push(1);
    assert_eq!(
        read(&wire, Some(u64::MAX), 0),
        (
            Err(native(NativeError::UnexpectedEnd { needed: 20 })),
            wire.len(),
            0,
            177
        )
    );
}

#[test]
fn huge_count_with_disabled_charging_fails_on_input_without_preallocation() {
    let mut wire = map_prefix(0);
    wire.push(253);
    wire.extend_from_slice(&u64::MAX.to_le_bytes());
    assert_eq!(
        read(&wire, None, 123),
        (
            Err(native(NativeError::UnexpectedEnd { needed: 20 })),
            wire.len(),
            0,
            123
        )
    );
    assert_eq!(
        read(&wire, Some(u64::MAX), 0),
        (Err(native(NativeError::LimitExceeded)), wire.len(), 0, 64)
    );
}

#[test]
fn three_records_preserve_wire_scalar_and_payload_order() {
    let mut wire = vec![0, 0, 0, 2];
    for (a, b, byte) in [(1, 2, 11), (3, 4, 22), (5, 6, 33)] {
        wire.extend_from_slice(&[a, b]);
        wire.extend_from_slice(&[byte; 2048]);
    }
    let (result, cursor, remaining, charged) = read(&wire, Some(u64::MAX), 0);
    let Greeting::Data2 {
        bytes,
        scalar,
        records,
    } = result.unwrap()
    else {
        panic!("expected Data2")
    };
    assert!(bytes.is_empty());
    assert_eq!(scalar, 0);
    for (actual, (a, b, byte)) in records.iter().zip([(1, 2, 11), (3, 4, 22), (5, 6, 33)]) {
        assert_eq!((actual.first, actual.second), (a, b));
        assert_eq!(actual.bytes, [byte; 2048]);
    }
    assert_eq!((cursor, remaining, charged), (wire.len(), 0, 6216));
}

#[test]
fn usize_errors_use_category_five_on_both_length_paths() {
    let prefix = [0, 0, 0, 2];
    for tail in [vec![254], vec![254; 9]] {
        let mut wire = prefix.to_vec();
        wire.extend_from_slice(&tail);
        let expected_cursor = if tail.len() > 8 { 4 } else { 5 };
        assert_eq!(
            read(&wire, None, 0),
            (
                Err(native(NativeError::InvalidIntegerType {
                    expected: 5,
                    found: 4
                })),
                expected_cursor,
                wire.len() - expected_cursor,
                0
            )
        );
    }
}

#[test]
fn nonminimal_scalars_and_selected_caller_trailing_bytes_are_accepted() {
    let wire = [
        1, 251, 0, 0, 252, 250, 0, 0, 0, 253, 1, 0, 0, 0, 0, 0, 0, 0, 99,
    ];
    let value = decode_with_limit(&wire, 28).unwrap();
    assert_eq!(value.greeting, Greeting::Triple([0, 250, 1]));
    assert_eq!(value.consumed, 18);
    assert_eq!(
        decode_with_limit(&[2], 3),
        Err(native(NativeError::LimitExceeded))
    );
}

#[test]
fn invalid_variant_reports_only_the_bound_active_fields() {
    assert_eq!(
        read(&[6], None, 0),
        (
            Err(native(NativeError::UnexpectedVariant {
                type_name: "AbciStreamGreeting",
                minimum: 0,
                maximum: 5,
                found: 6
            })),
            1,
            0,
            0
        )
    );
    assert_eq!(
        read(&[0, 0, 0, 3], None, 0),
        (
            Err(native(NativeError::UnexpectedVariant {
                type_name: "GreetingHash",
                minimum: 0,
                maximum: 2,
                found: 3
            })),
            4,
            0,
            0
        )
    );
}

#[test]
fn safe_cursor_construction_and_nonzero_cursor_are_explicit() {
    assert_eq!(
        Reader::new(&[2], 2, None, 0).unwrap_err(),
        StateError::CursorOutOfBounds
    );
    let mut reader = Reader::new(&[255, 2, 99], 1, None, u64::MAX).unwrap();
    assert_eq!(reader.decode(), Ok(Greeting::Empty2));
    assert_eq!(
        (reader.cursor(), reader.remaining(), reader.charged()),
        (2, 1, u64::MAX)
    );
    assert_eq!(reader.remaining_bytes(), &[99]);
}
