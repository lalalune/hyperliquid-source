use std::cell::Cell;
use std::collections::BTreeMap;
use std::sync::Arc;

use node94_consensus_admission::client_transaction_join::{
    checked_row_bytes, join_transactions, ClientJoinInput, JoinError, JoinedTransaction,
};
use node94_consensus_admission::TransactionHash;

fn hash(value: u8) -> TransactionHash {
    let mut bytes = [0; 32];
    bytes[31] = value;
    TransactionHash(bytes)
}

fn input<T>(block: Arc<T>) -> ClientJoinInput<T> {
    ClientJoinInput {
        block,
        rows: None,
        time: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
    }
}

#[test]
fn supplied_rows_preserve_both_arcs_and_ignore_invalid_views() {
    let block = Arc::new((vec![0, 255, 8], Some(vec![9, 0, 1])));
    let value = Arc::new(vec![4, 3, 2]);
    let rows = Arc::new(vec![JoinedTransaction {
        hash: hash(8),
        bytes: Arc::clone(&value),
    }]);
    let h = Cell::new(0);
    let m = Cell::new(0);
    let mut supplied = input(Arc::clone(&block));
    supplied.rows = Some(Arc::clone(&rows));
    let result = join_transactions(
        supplied,
        || {
            h.set(h.get() + 1);
            Err("invalid hash view")
        },
        || {
            m.set(m.get() + 1);
            Err("invalid map view")
        },
    )
    .unwrap();
    assert!(Arc::ptr_eq(&result.block, &block));
    assert!(Arc::ptr_eq(&result.rows, &rows));
    assert!(Arc::ptr_eq(&result.rows[0].bytes, &value));
    assert_eq!(result.time, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
    assert_eq!((h.get(), m.get()), (0, 0));
}

#[test]
fn supplied_empty_is_distinct_from_absent_empty() {
    let keeper = Arc::new(Vec::new());
    let mut supplied = input(Arc::new(()));
    supplied.rows = Some(Arc::clone(&keeper));
    let passed = join_transactions(supplied, || Err("hash"), || Err("map")).unwrap();
    assert!(Arc::ptr_eq(&passed.rows, &keeper));

    let h = Cell::new(0);
    let m = Cell::new(0);
    let empty = join_transactions(
        input(Arc::new(())),
        || {
            h.set(h.get() + 1);
            Ok::<_, &str>(&[][..])
        },
        || {
            m.set(m.get() + 1);
            Err("invalid unused map")
        },
    )
    .unwrap();
    assert_eq!((h.get(), m.get()), (1, 0));
    assert!(empty.rows.is_empty());
    assert!(!Arc::ptr_eq(&empty.rows, &keeper));
    assert_eq!(Arc::strong_count(&empty.rows), 1);
}

#[test]
fn request_order_repetition_and_shared_values_are_preserved() {
    let a = Arc::new(vec![1]);
    let b = Arc::new(vec![2]);
    let map = BTreeMap::from([(hash(1), Arc::clone(&a)), (hash(2), Arc::clone(&b))]);
    let hashes = [hash(2), hash(1), hash(2), hash(1)];
    let result = join_transactions(
        input(Arc::new(vec![9, 8, 7])),
        || Ok::<_, ()>(&hashes[..]),
        || Ok(&map),
    )
    .unwrap();
    assert_eq!(
        result.rows.iter().map(|x| x.hash).collect::<Vec<_>>(),
        hashes
    );
    assert!(Arc::ptr_eq(&result.rows[0].bytes, &b));
    assert!(Arc::ptr_eq(&result.rows[1].bytes, &a));
    assert!(Arc::ptr_eq(&result.rows[0].bytes, &result.rows[2].bytes));
    assert_eq!((Arc::strong_count(&a), Arc::strong_count(&b)), (4, 4));
    drop(result);
    assert_eq!((Arc::strong_count(&a), Arc::strong_count(&b)), (2, 2));
}

#[test]
fn equal_bytes_do_not_merge_distinct_value_objects() {
    let a = Arc::new(b"equal bytes".to_vec());
    let b = Arc::new(b"equal bytes".to_vec());
    let map = BTreeMap::from([(hash(1), Arc::clone(&a)), (hash(2), Arc::clone(&b))]);
    let hashes = [hash(2), hash(1)];
    let result = join_transactions(
        input(Arc::new(())),
        || Ok::<_, ()>(&hashes[..]),
        || Ok(&map),
    )
    .unwrap();
    assert!(Arc::ptr_eq(&result.rows[0].bytes, &b));
    assert!(Arc::ptr_eq(&result.rows[1].bytes, &a));
    assert!(!Arc::ptr_eq(&result.rows[0].bytes, &result.rows[1].bytes));
}

#[test]
fn first_missing_consumes_block_and_releases_aliased_prefix() {
    let shared = Arc::new(vec![255, 128, 0]);
    let map = BTreeMap::from([
        (hash(1), Arc::clone(&shared)),
        (hash(2), Arc::clone(&shared)),
    ]);
    let hashes = [hash(1), hash(2), hash(1), hash(9), hash(8)];
    let block = Arc::new(vec![0, 255]);
    let weak = Arc::downgrade(&block);
    let result = join_transactions(input(block), || Ok::<_, ()>(&hashes[..]), || Ok(&map));
    assert!(matches!(result, Err(JoinError::MissingTransaction(h)) if h == hash(9)));
    assert!(weak.upgrade().is_none());
    assert_eq!(Arc::strong_count(&shared), 3);
    assert_eq!(map.len(), 2);
    assert!(Arc::ptr_eq(&map[&hash(1)], &map[&hash(2)]));
}

#[test]
fn empty_map_reports_first_request_without_returning_a_prefix() {
    let map = BTreeMap::new();
    let hashes = [hash(9), hash(1)];
    let result = join_transactions(
        input(Arc::new(())),
        || Ok::<_, ()>(&hashes[..]),
        || Ok(&map),
    );
    assert!(matches!(result, Err(JoinError::MissingTransaction(h)) if h == hash(9)));
}

#[test]
fn views_are_invoked_once_and_safe_errors_are_distinct() {
    let block = Arc::new(());
    let weak = Arc::downgrade(&block);
    let m = Cell::new(0);
    let failed = join_transactions(
        input(block),
        || Err("hash"),
        || {
            m.set(m.get() + 1);
            Err("map")
        },
    );
    assert!(matches!(failed, Err(JoinError::HashView("hash"))));
    assert_eq!(m.get(), 0);
    assert!(weak.upgrade().is_none());

    let hashes = [hash(1)];
    let h = Cell::new(0);
    let failed = join_transactions(
        input(Arc::new(())),
        || {
            h.set(h.get() + 1);
            Ok(&hashes[..])
        },
        || {
            m.set(m.get() + 1);
            Err("map")
        },
    );
    assert!(matches!(failed, Err(JoinError::MapView("map"))));
    assert_eq!((h.get(), m.get()), (1, 1));
}

#[test]
fn every_key_byte_and_unsigned_order_remain_significant() {
    for index in 0..32 {
        let mut a = [85; 32];
        let mut b = a;
        a[index] = 127;
        b[index] = 128;
        let a = TransactionHash(a);
        let b = TransactionHash(b);
        let map = BTreeMap::from([(a, Arc::new(vec![1])), (b, Arc::new(vec![2]))]);
        let hashes = [b, a, b];
        let result = join_transactions(
            input(Arc::new(())),
            || Ok::<_, ()>(&hashes[..]),
            || Ok(&map),
        )
        .unwrap();
        assert_eq!(
            result.rows.iter().map(|r| r.hash).collect::<Vec<_>>(),
            hashes
        );
        assert_eq!(result.rows[0].bytes.as_slice(), &[2]);
        assert_eq!(result.rows[1].bytes.as_slice(), &[1]);
    }
}

#[test]
fn large_ordered_map_has_no_native_shape_or_byte_hash_dependency() {
    let map = (0..=255)
        .map(|i| (hash(i), Arc::new(vec![255 - i])))
        .collect::<BTreeMap<_, _>>();
    let hashes = [hash(255), hash(0), hash(129), hash(128), hash(255)];
    let result = join_transactions(
        input(Arc::new(())),
        || Ok::<_, ()>(&hashes[..]),
        || Ok(&map),
    )
    .unwrap();
    assert_eq!(
        result.rows.iter().map(|r| r.bytes[0]).collect::<Vec<_>>(),
        [0, 255, 126, 127, 0]
    );
    assert_eq!(map.len(), 256);
}

#[test]
fn checked_native_span_rejects_overflow_without_allocating() {
    assert_eq!(checked_row_bytes(0), Some(0));
    assert_eq!(checked_row_bytes(1), Some(40));
    let host_limit = (isize::MAX as u64).min(i64::MAX as u64) / 40;
    assert_eq!(
        checked_row_bytes(host_limit),
        Some((host_limit * 40) as usize)
    );
    assert_eq!(checked_row_bytes(host_limit + 1), None);
    assert_eq!(checked_row_bytes(u64::MAX), None);
}

#[test]
fn new_rows_preserve_the_original_opaque_block_pointer() {
    let block = Arc::new((vec![7, 0, 255], Some(vec![2, 3, 4])));
    let weak = Arc::downgrade(&block);
    let values = BTreeMap::from([(hash(3), Arc::new(vec![8, 9]))]);
    let hashes = [hash(3)];
    let result =
        join_transactions(input(block), || Ok::<_, ()>(&hashes[..]), || Ok(&values)).unwrap();
    assert!(std::ptr::eq(weak.as_ptr(), Arc::as_ptr(&result.block)));
    assert_eq!(
        result.block.as_ref(),
        &(vec![7, 0, 255], Some(vec![2, 3, 4]))
    );
    assert_eq!(Arc::strong_count(&result.block), 1);
    drop(result);
    assert!(weak.upgrade().is_none());
}
