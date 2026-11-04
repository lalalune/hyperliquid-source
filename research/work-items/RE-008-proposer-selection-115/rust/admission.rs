// SPDX-License-Identifier: MIT
#[path = "lib.rs"]
mod projection;
use projection::*;

#[test]
fn refuses_invalid_order_and_duplicate_keys() {
    assert_eq!(history(0, &[2, 1], 0), Err(Failure::InvalidSnapshot));
    assert_eq!(history(0, &[1, 1], 0), Err(Failure::InvalidSnapshot));
    assert!(matches!(prepare(&[[0; 20], [0; 20]], &[], &[]), Err(Failure::InvalidSnapshot)));
    assert!(matches!(prepare(&[], &[], &[([1; 20], 0), ([0; 20], 1)]), Err(Failure::InvalidSnapshot)));
}

#[test]
fn ring_validates_logical_order_and_capacity_only() {
    assert_eq!(ring_history(&[], 1, 0, 0), Err(Failure::InvalidSnapshot));
    assert_eq!(ring_history(&[1], 0, 2, 0), Err(Failure::InvalidSnapshot));
    assert_eq!(ring_history(&[1], 1, 0, 0), Err(Failure::InvalidSnapshot));
    assert_eq!(ring_history(&[4, 99, 3], 2, 2, 4), Ok((2, Some(0))));
    assert_eq!(ring_history(&[2, 99, 3], 2, 2, 4), Err(Failure::InvalidSnapshot));
}

#[test]
fn missing_first_does_not_validate_second() {
    let first = History::<Vec<Key>> { base: 0, snapshots: vec![] };
    let second = History { base: 0, snapshots: vec![(2, vec![]), (1, vec![])] };
    match from_histories(&first, &second, &[], 17, 2000, 0, u64::MAX, [0xa5; 72], [0x5a; 72]).unwrap() {
        HistoryResult::Missing { second, counter, image, .. } => {
            assert!(second.is_none());
            assert_eq!(counter, 0);
            assert_eq!(image[0], MISSING);
            assert_eq!(&image[8..16], &2000u64.to_le_bytes());
            assert!(image[1..8].iter().chain(image[16..].iter()).all(|&x| x == 0xa5));
        }
        _ => panic!("missing first must short circuit"),
    }
}

#[test]
fn missing_second_increments_twice_and_keeps_scratch_padding() {
    let first = History { base: 0, snapshots: vec![(0, vec![])] };
    let second = History::<Vec<Row>> { base: 0, snapshots: vec![] };
    match from_histories(&first, &second, &[], 1, 2000, 0, u64::MAX, [3; 72], [4; 72]).unwrap() {
        HistoryResult::Missing { second, counter, image, .. } => {
            assert!(second.is_some());
            assert_eq!(counter, 1);
            assert_eq!(image[71], 3);
        }
        _ => panic!("missing second"),
    }
}

#[test]
fn refuses_unrepresentable_schedule_without_changing_value_input() {
    let image = [0x76; 72];
    assert!(matches!(schedule(&[], &[], &[([1; 20], u64::MAX)], 0, image), Err(Failure::Capacity)));
    assert_eq!(image, [0x76; 72]);
}

#[test]
fn arithmetic_admission_is_explicit() {
    for args in [(0, 0, 1, 0), (0, 1, 0, 0), (1, 1, 1, 0), (0, 1, 1, 1), (1 << 63, u64::MAX, 1, 0)] {
        assert_eq!(event_bits(args.0, args.1, args.2, args.3), Err(Failure::InvalidSnapshot));
    }
}
