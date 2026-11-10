//! `SigMap::from_normalized` takes the output of `node115-certificate-long-sort` (stable sort, last row
//! of a repeated key wins, at most 64 rows: ring, more: tree) as the certificate's signature collection.

use node115_certificate_long_sort::{QcRow, normalize_qc};
use node115_nested_certificate_decision::sigmap::SigMap;

fn row(first: u8, second: u8, marker: u8) -> QcRow {
    let mut key = [0u8; 20];
    key[0] = first;
    key[1] = second;
    let mut tail = [marker; 76];
    for (i, b) in tail.iter_mut().enumerate() {
        *b = marker.wrapping_add(i as u8);
    }
    QcRow { key, tail }
}

#[test]
fn flat_normalization_becomes_a_ring_in_key_order_with_the_last_duplicate() {
    let rows = [row(9, 0, 10), row(3, 0, 20), row(9, 0, 30), row(5, 0, 40)];
    let map = SigMap::from_normalized(&normalize_qc(&rows));
    let SigMap::Ring { head, len, .. } = &map else { panic!("expected a ring") };
    assert_eq!((*head, *len), (0, 3));
    let keys: Vec<u8> = map.entries().iter().map(|(k, _)| k[0]).collect();
    assert_eq!(keys, [3, 5, 9]);
    let nine = map.entries()[2];
    // Signature bytes are tail[4..69] of the surviving (third) row.
    let want: Vec<u8> = (4..69u8).map(|i| 30u8.wrapping_add(i)).collect();
    assert_eq!(nine.1.as_slice(), want.as_slice());
}

#[test]
fn more_than_64_rows_become_a_tree() {
    let rows: Vec<QcRow> = (0..65u8).rev().map(|i| row(i, 1, i)).collect();
    let map = SigMap::from_normalized(&normalize_qc(&rows));
    assert!(matches!(map, SigMap::Tree(_)));
    assert_eq!(map.len(), 65);
    let keys: Vec<u8> = map.entries().iter().map(|(k, _)| k[0]).collect();
    assert_eq!(keys, (0..65u8).collect::<Vec<_>>());
    let exactly_64: Vec<QcRow> = (0..64u8).map(|i| row(i, 1, i)).collect();
    assert!(matches!(SigMap::from_normalized(&normalize_qc(&exactly_64)), SigMap::Ring { .. }));
}
