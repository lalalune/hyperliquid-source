#![cfg(feature = "timed-stream")]

use node94_tcp_frame::evm_kvs::{ErrorKind, Failure, Message, TransferSize, decode};

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

fn widths(n: u8) -> [Vec<u8>; 4] {
    [
        vec![n],
        vec![251, n, 0],
        vec![252, n, 0, 0, 0],
        vec![253, n, 0, 0, 0, 0, 0, 0, 0],
    ]
}

fn batch(rows: &[(&[u8], &[u8])]) -> Vec<u8> {
    let mut bytes = vec![0];
    bytes.extend(word(rows.len() as u64));
    for (first, second) in rows {
        bytes.extend(word(first.len() as u64));
        bytes.extend_from_slice(first);
        bytes.extend(word(second.len() as u64));
        bytes.extend_from_slice(second);
    }
    bytes
}

fn failure(input: &[u8], limit: u64, kind: ErrorKind, consumed: usize, charged: u64) {
    assert_eq!(
        decode(input, limit).unwrap_err(),
        Failure {
            kind,
            consumed,
            charged,
        }
    );
}

#[test]
fn unit_and_empty_batch_have_distinct_values_charges_and_suffixes() {
    for input in [vec![1], vec![251, 1, 0], vec![252, 1, 0, 0, 0]] {
        let mut with_suffix = input.clone();
        with_suffix.extend([0xaa, 0xbb]);
        let got = decode(&with_suffix, 4).unwrap();
        assert_eq!(got.message, Message::End);
        assert_eq!(
            (got.consumed, got.remaining, got.charged),
            (input.len(), 2, 4)
        );
    }
    let got = decode(&[0, 0, 0xff], 12).unwrap();
    assert_eq!(got.message, Message::Batch(Vec::new()));
    assert_eq!((got.consumed, got.remaining, got.charged), (2, 1, 12));
}

#[test]
fn cumulative_transfer_bytes_exclude_wire_and_logical_overhead() {
    let input = batch(&[(&[0xaa, 0xbb], &[0xff]), (&[], &[])]);
    let decoded = decode(&input, 76).unwrap();
    assert_eq!(decoded.charged, 47);
    let Message::Batch(rows) = decoded.message else {
        panic!("wrong variant");
    };
    let mut size = TransferSize::default();
    size.account_batch(&rows).unwrap();
    assert_eq!(size.total(), 3);
    assert!(decoded.consumed > size.total() as usize);
}

#[test]
fn raw_rows_preserve_order_duplicates_empty_values_and_non_utf8() {
    let rows: [(&[u8], &[u8]); 4] = [
        (&[0xff, 0], &[0x80, 1]),
        (&[], &[]),
        (&[0xff, 0], &[2]),
        (&[0], &[0xff]),
    ];
    let input = batch(&rows);
    let got = decode(&input, 140).unwrap();
    let Message::Batch(decoded) = got.message else {
        panic!("wrong variant");
    };
    assert_eq!(decoded.len(), rows.len());
    for ((first, second), (want_first, want_second)) in decoded.iter().zip(rows) {
        assert_eq!(first.as_ref(), want_first);
        assert_eq!(second.as_ref(), want_second);
    }
    assert_eq!(
        (got.consumed, got.remaining, got.charged),
        (input.len(), 0, 85)
    );
}

#[test]
fn all_count_and_array_length_widths_allow_nonminimal_encodings() {
    for count in widths(1) {
        for first in widths(0) {
            for second in widths(0) {
                let input = [vec![0], count.clone(), first.clone(), second, vec![0xaa]].concat();
                let got = decode(&input, 44).unwrap();
                assert_eq!(
                    got.message,
                    Message::Batch(vec![(Box::new([]), Box::new([]))])
                );
                assert_eq!(
                    (got.consumed, got.remaining, got.charged),
                    (input.len() - 1, 1, 28)
                );
            }
        }
    }
}

#[test]
fn truncating_every_wire_position_preserves_reached_cursor_and_charge() {
    let input = [0, 2, 2, 0xaa, 0xff, 1, 0x80, 0, 2, 0xfe, 0xff];
    // Frozen expectations from the native charge/refund and byte-array checks.
    let expected = [
        (ErrorKind::UnexpectedEnd { needed: 1 }, 0, 4),
        (ErrorKind::UnexpectedEnd { needed: 1 }, 1, 12),
        (ErrorKind::UnexpectedEnd { needed: 1 }, 2, 52),
        (ErrorKind::CollectionTooLong, 3, 54),
        (ErrorKind::CollectionTooLong, 3, 54),
        (ErrorKind::UnexpectedEnd { needed: 1 }, 5, 62),
        (ErrorKind::CollectionTooLong, 6, 63),
        (ErrorKind::UnexpectedEnd { needed: 1 }, 7, 39),
        (ErrorKind::UnexpectedEnd { needed: 1 }, 8, 47),
        (ErrorKind::CollectionTooLong, 9, 49),
        (ErrorKind::CollectionTooLong, 9, 49),
    ];
    for (len, (kind, consumed, charged)) in expected.into_iter().enumerate() {
        failure(&input[..len], 76, kind, consumed, charged);
    }
    let got = decode(&input, 76).unwrap();
    assert_eq!((got.consumed, got.remaining, got.charged), (11, 0, 49));
}

#[test]
fn budgets_check_peak_reservation_before_final_smaller_charge() {
    let input = [0, 2, 2, 0xaa, 0xff, 1, 0x80, 0, 2, 0xfe, 0xff];
    for limit in [0, 3] {
        failure(&input, limit, ErrorKind::Limit, 0, 4);
    }
    for limit in [4, 11] {
        failure(&input, limit, ErrorKind::Limit, 1, 12);
    }
    for limit in [12, 49, 75] {
        failure(&input, limit, ErrorKind::Limit, 2, 76);
    }
    assert_eq!(decode(&input, 76).unwrap().charged, 49);
}

#[test]
fn later_array_cost_can_exceed_the_initial_reservation() {
    let input = batch(&[(&[0xaa; 40], &[]), (&[], &[])]);
    for limit in 0..100 {
        let (consumed, charged) = match limit {
            0..=3 => (0, 4),
            4..=11 => (1, 12),
            12..=75 => (2, 76),
            76..=91 => (3, 92),
            _ => (43, 100),
        };
        failure(&input, limit, ErrorKind::Limit, consumed, charged);
    }
    let got = decode(&input, 100).unwrap();
    assert_eq!(
        (got.consumed, got.remaining, got.charged),
        (input.len(), 0, 84)
    );
}

#[test]
fn overflow_never_stores_the_failed_increment() {
    for count in [1 << 59, u64::MAX] {
        let input = [vec![0], word(count)].concat();
        failure(&input, u64::MAX, ErrorKind::Limit, input.len(), 12);
    }
    let max_count = u64::MAX / 32;
    let prefix = [vec![0], word(max_count)].concat();
    failure(&prefix, u64::MAX - 20, ErrorKind::Limit, 10, u64::MAX - 19);
    let input = [prefix.clone(), vec![60]].concat();
    failure(&input, u64::MAX, ErrorKind::Limit, 11, u64::MAX - 43);
    let input = [prefix, vec![43], vec![0xaa; 43]].concat();
    failure(&input, u64::MAX, ErrorKind::Limit, 54, u64::MAX);
    let input = [vec![0, 1], word(u64::MAX)].concat();
    failure(&input, u64::MAX, ErrorKind::Limit, 11, 20);
}

#[test]
fn sequence_count_is_not_prechecked_against_remaining_bytes() {
    failure(&[0, 1], 44, ErrorKind::UnexpectedEnd { needed: 1 }, 2, 20);
    failure(
        &[0, 1, 0],
        44,
        ErrorKind::UnexpectedEnd { needed: 1 },
        3,
        28,
    );
    failure(&[0, 2], 75, ErrorKind::Limit, 2, 76);
}

#[test]
fn each_array_checks_its_own_declared_length_after_charging() {
    failure(
        &[0, 1, 3, 0xaa, 0xbb],
        44,
        ErrorKind::CollectionTooLong,
        3,
        23,
    );
    failure(
        &[0, 1, 1, 0xaa, 3, 0xbb],
        44,
        ErrorKind::CollectionTooLong,
        5,
        32,
    );
}

#[test]
fn array_budget_failure_precedes_payload_availability_failure() {
    let first_short = [0, 1, 50, 0xaa];
    failure(&first_short, 69, ErrorKind::Limit, 3, 70);
    failure(&first_short, 70, ErrorKind::CollectionTooLong, 3, 70);
    let second_short = [0, 1, 0, 50, 0xaa];
    failure(&second_short, 77, ErrorKind::Limit, 4, 78);
    failure(&second_short, 78, ErrorKind::CollectionTooLong, 4, 78);
}

#[test]
fn short_integer_extensions_consume_only_the_marker() {
    failure(
        &[251, 1],
        1000,
        ErrorKind::UnexpectedEnd { needed: 1 },
        1,
        4,
    );
    failure(
        &[0, 251, 7],
        1000,
        ErrorKind::UnexpectedEnd { needed: 1 },
        2,
        12,
    );
    failure(
        &[0, 1, 252, 7],
        1000,
        ErrorKind::UnexpectedEnd { needed: 3 },
        3,
        20,
    );
    failure(
        &[0, 1, 0, 253, 1, 2],
        1000,
        ErrorKind::UnexpectedEnd { needed: 6 },
        4,
        28,
    );
}

#[test]
fn every_truncated_extension_at_each_integer_position_keeps_the_marker_only() {
    for (prefix, value, charged, maximum_width) in [
        (vec![], 0, 4, 5),
        (vec![0], 1, 12, 9),
        (vec![0, 1], 0, 20, 9),
        (vec![0, 1, 0], 0, 28, 9),
    ] {
        for encoded in widths(value).into_iter().skip(1) {
            if encoded.len() > maximum_width {
                continue;
            }
            for length in 0..encoded.len() {
                let mut input = prefix.clone();
                input.extend_from_slice(&encoded[..length]);
                let (consumed, needed) = if length == 0 {
                    (prefix.len(), 1)
                } else {
                    (prefix.len() + 1, (encoded.len() - length) as u64)
                };
                failure(
                    &input,
                    1000,
                    ErrorKind::UnexpectedEnd { needed },
                    consumed,
                    charged,
                );
            }
        }
    }
}

#[test]
fn invalid_selectors_are_decoded_before_variant_rejection() {
    for tag in 2..=250 {
        failure(
            &[tag],
            4,
            ErrorKind::UnexpectedVariant {
                type_name: "EvmKvsMsg",
                found: tag as u32,
                max: 1,
            },
            1,
            4,
        );
    }
    let input = [vec![252], u32::MAX.to_le_bytes().to_vec()].concat();
    failure(
        &input,
        4,
        ErrorKind::UnexpectedVariant {
            type_name: "EvmKvsMsg",
            found: u32::MAX,
            max: 1,
        },
        5,
        4,
    );
}

#[test]
fn invalid_u32_markers_keep_fast_and_slow_cursor_behavior() {
    for (marker, found) in [(253, 3), (254, 4), (255, 12)] {
        for len in [1, 4, 5, 9] {
            let mut input = vec![0; len];
            input[0] = marker;
            failure(
                &input,
                1000,
                ErrorKind::InvalidIntegerType { expected: 2, found },
                usize::from(len <= 4),
                4,
            );
        }
    }
}

#[test]
fn invalid_u64_markers_cover_count_and_both_array_positions() {
    for prefix in [vec![0], vec![0, 1], vec![0, 1, 0]] {
        let charged = match prefix.len() {
            1 => 12,
            2 => 20,
            _ => 28,
        };
        for (marker, found) in [(254, 4), (255, 12)] {
            for trailing in [0, 7, 8] {
                let mut input = prefix.clone();
                input.push(marker);
                input.extend(vec![0; trailing]);
                let fast = trailing >= 8;
                failure(
                    &input,
                    1000,
                    ErrorKind::InvalidIntegerType {
                        expected: if fast { 2 } else { 3 },
                        found,
                    },
                    prefix.len() + usize::from(!fast),
                    charged,
                );
            }
        }
    }
}

#[test]
fn error_display_identifies_evm_kvs_without_claiming_native_text() {
    use std::error::Error;

    let error = decode(&[], 4).unwrap_err();
    assert!(error.to_string().starts_with("EVM KVS decode at byte 0:"));
    assert!(!error.to_string().contains("greeting"));
    assert!(error.source().is_none());
}
