//! Fixed expectations from the pre-source contract, separate from the TSV driver.
use node94_funding_record_storage::{Record, apply_returned_records};
use std::collections::BTreeMap;

fn row(key: u64, tag: u64, payload: u64) -> Record {
    Record { key, tag, payload }
}

#[test]
fn empty_stream_preserves_entry_presence_and_initial_values() {
    let mut samples = BTreeMap::from([(7, vec![]), (9, vec![11])]);
    let mut fallbacks = BTreeMap::from([(2, 13)]);
    apply_returned_records(&mut samples, &mut fallbacks, 3, &[]);
    assert_eq!(samples, BTreeMap::from([(7, vec![]), (9, vec![11])]));
    assert_eq!(fallbacks, BTreeMap::from([(2, 13)]));
}

#[test]
fn full_width_sentinel_stops_before_parity_or_later_updates() {
    let mut samples = BTreeMap::new();
    let mut fallbacks = BTreeMap::from([(7, 90)]);
    let records = [row(7, 0, 1), row(7, 2, 2), row(7, 0, 3), row(7, 1, 4)];
    apply_returned_records(&mut samples, &mut fallbacks, 3, &records);
    assert_eq!(samples, BTreeMap::from([(7, vec![1])]));
    assert_eq!(fallbacks, BTreeMap::from([(7, 90)]));
}

#[test]
fn wide_tags_use_full_stop_test_then_low_bit() {
    let mut samples = BTreeMap::new();
    let mut fallbacks = BTreeMap::new();
    let records = [
        row(7, 0x102, 1),
        row(7, 0x8000_0000_0000_0002, 2),
        row(7, 0x8000_0000_0000_0000, 3),
        row(7, 3, 4),
        row(7, u64::MAX, 5),
    ];
    apply_returned_records(&mut samples, &mut fallbacks, 3, &records);
    assert_eq!(samples, BTreeMap::from([(7, vec![1, 2, 3])]));
    assert_eq!(fallbacks, BTreeMap::from([(7, 5)]));
}

#[test]
fn every_dex_byte_uses_exact_three_guard() {
    for dex_byte in 0_u8..=u8::MAX {
        let mut samples = BTreeMap::from([(7, vec![10])]);
        let mut fallbacks = BTreeMap::from([(7, 80)]);
        apply_returned_records(
            &mut samples,
            &mut fallbacks,
            dex_byte,
            &[row(7, 0, 11), row(7, 1, 12)],
        );
        assert_eq!(samples, BTreeMap::from([(7, vec![10, 11])]));
        assert_eq!(fallbacks[&7], if dex_byte == 3 { 12 } else { 80 });
    }
}

#[test]
fn repeated_appends_preserve_initial_order_and_unrelated_entries() {
    let mut samples = BTreeMap::from([(1, vec![]), (7, vec![0]), (9, vec![u64::MAX])]);
    let mut fallbacks = BTreeMap::from([(9, 6)]);
    apply_returned_records(
        &mut samples,
        &mut fallbacks,
        3,
        &[row(7, 0, 1), row(8, 4, 2), row(7, 4, 3)],
    );
    assert_eq!(
        samples,
        BTreeMap::from([
            (1, vec![]),
            (7, vec![0, 1, 3]),
            (8, vec![2]),
            (9, vec![u64::MAX])
        ])
    );
    assert_eq!(fallbacks, BTreeMap::from([(9, 6)]));
}

#[test]
fn last_fallback_replaces_existing_and_does_not_create_sample() {
    let mut samples = BTreeMap::from([(1, vec![])]);
    let mut fallbacks = BTreeMap::from([(7, 0), (9, 4)]);
    apply_returned_records(
        &mut samples,
        &mut fallbacks,
        3,
        &[row(7, 1, 1), row(8, 3, 2), row(7, 5, 3)],
    );
    assert_eq!(samples, BTreeMap::from([(1, vec![])]));
    assert_eq!(fallbacks, BTreeMap::from([(7, 3), (8, 2), (9, 4)]));
}

#[test]
fn payload_bits_and_unsigned_key_order_survive() {
    let mut samples = BTreeMap::new();
    let mut fallbacks = BTreeMap::new();
    let records = [
        row(u64::MAX, 0, 0x7ff8_0000_0000_0042),
        row(0, 0, 0x8000_0000_0000_0000),
        row(1 << 63, 0, 0x7ff0_0000_0000_0001),
        row((1 << 63) - 1, 0, u64::MAX),
    ];
    apply_returned_records(&mut samples, &mut fallbacks, 3, &records);
    assert_eq!(
        samples.into_iter().collect::<Vec<_>>(),
        vec![
            (0, vec![0x8000_0000_0000_0000]),
            ((1 << 63) - 1, vec![u64::MAX]),
            (1 << 63, vec![0x7ff0_0000_0000_0001]),
            (u64::MAX, vec![0x7ff8_0000_0000_0042]),
        ]
    );
    assert!(fallbacks.is_empty());
}

#[test]
fn record_inputs_are_unchanged_and_stop_is_per_supplied_stream() {
    let records = [row(7, 2, 99), row(7, 0, 100)];
    let before = records;
    let mut samples = BTreeMap::new();
    let mut fallbacks = BTreeMap::new();
    apply_returned_records(&mut samples, &mut fallbacks, 3, &records);
    assert!(samples.is_empty());
    apply_returned_records(&mut samples, &mut fallbacks, 3, &records[1..]);
    assert_eq!(samples, BTreeMap::from([(7, vec![100])]));
    assert_eq!(records, before);
}
