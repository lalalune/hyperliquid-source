use node115_certificate_long_sort::*;
use std::collections::BTreeMap;

fn row<const N: usize>(key: usize, position: usize) -> Row<N> {
    let mut out = Row {
        key: [0; 20],
        tail: [0; N],
    };
    out.key[12..].copy_from_slice(&(key as u64).to_be_bytes());
    for (i, byte) in out.tail.iter_mut().enumerate() {
        *byte = ((position.wrapping_mul(73) ^ (position >> (i % 8)) ^ i) & 255) as u8;
    }
    out.tail[..8].copy_from_slice(&(position as u64).to_le_bytes());
    out
}

// Independent expectation: a key-indexed overwrite ledger, not a second sort
// or a call to the implementation's merge/compaction routines.
fn oracle<const N: usize>(input: &[Row<N>]) -> Vec<Row<N>> {
    let mut last = BTreeMap::new();
    for r in input {
        last.insert(r.key, r.clone());
    }
    last.into_values().collect()
}

fn check_qc(keys: &[usize]) {
    let input: Vec<_> = keys.iter().enumerate().map(|(i, &k)| row(k, i)).collect();
    let actual = normalize_qc(&input);
    let expected = oracle(&input);
    assert_eq!(
        actual.storage,
        if expected.len() <= 64 {
            StorageClass::Flat
        } else {
            StorageClass::Tree
        }
    );
    assert_eq!(actual.rows, expected);
}

fn check_tc(keys: &[usize]) {
    let input: Vec<_> = keys.iter().enumerate().map(|(i, &k)| row(k, i)).collect();
    let actual = normalize_tc(&input);
    let expected = oracle(&input);
    assert_eq!(
        actual.storage,
        if expected.len() <= 64 {
            StorageClass::Flat
        } else {
            StorageClass::Tree
        }
    );
    assert_eq!(actual.rows, expected);
}

#[test]
fn conflicting_duplicates_cross_sort_small_helper_and_container_boundaries() {
    for n in [
        0, 1, 2, 7, 8, 19, 20, 21, 31, 32, 33, 63, 64, 65, 66, 127, 128, 129, 257,
    ] {
        let patterns: Vec<Vec<usize>> = vec![
            (0..n).collect(),
            (0..n).rev().collect(),
            vec![5; n],
            (0..n).map(|i| i % 3).collect(),
            (0..n).map(|i| (i * 37 + 11) % 67).collect(),
            (0..n)
                .map(|i| if i < n / 2 { i % 17 } else { (n - i) % 17 })
                .collect(),
        ];
        for keys in patterns {
            check_qc(&keys);
            check_tc(&keys);
        }
    }
}

#[test]
fn natural_runs_do_not_reverse_equal_key_groups() {
    let keys: Vec<_> = (0..40).rev().flat_map(|k| [k, k, k]).collect();
    check_qc(&keys);
    check_tc(&keys);
}

#[test]
fn duplicates_across_run_edges_keep_the_last_original_whole_row() {
    let mut keys: Vec<_> = (0..97).collect();
    for i in [0, 19, 20, 31, 32, 33, 63, 64, 65, 96] {
        keys[i] = 7;
    }
    let qc: Vec<_> = keys.iter().enumerate().map(|(i, &k)| row(k, i)).collect();
    let tc: Vec<_> = keys.iter().enumerate().map(|(i, &k)| row(k, i)).collect();
    assert_eq!(
        normalize_qc(&qc).rows.iter().find(|r| r.key == qc[96].key),
        Some(&qc[96])
    );
    assert_eq!(
        normalize_tc(&tc).rows.iter().find(|r| r.key == tc[96].key),
        Some(&tc[96])
    );
    check_qc(&keys);
    check_tc(&keys);
}

#[test]
fn every_key_byte_is_significant_and_every_tail_byte_is_preserved() {
    for byte in 0..20 {
        let mut a: QcRow = row(0, 1);
        let mut b: QcRow = row(0, 2);
        a.key[byte] = 0x7f;
        b.key[byte] = 0x80;
        assert_eq!(
            normalize_qc(&[b.clone(), a.clone()]).rows,
            vec![a.clone(), b]
        );
        for tail_byte in 0..76 {
            let mut later = a.clone();
            later.tail[tail_byte] ^= 1;
            assert_eq!(normalize_qc(&[a.clone(), later.clone()]).rows, vec![later]);
        }
    }
    let base: TcRow = row(4, 1);
    for byte in 0..84 {
        let mut later = base.clone();
        later.tail[byte] ^= 1;
        assert_eq!(
            normalize_tc(&[base.clone(), later.clone()]).rows,
            vec![later]
        );
    }
}

#[test]
fn container_threshold_uses_retained_count_not_input_count() {
    let sixty_five: Vec<_> = (0..65).map(|i| row(i, i)).collect();
    assert_eq!(normalize_qc(&sixty_five).storage, StorageClass::Tree);
    let mut duplicate = sixty_five;
    duplicate[64].key = duplicate[0].key;
    let normalized = normalize_qc(&duplicate);
    assert_eq!(normalized.rows.len(), 64);
    assert_eq!(normalized.storage, StorageClass::Flat);
    assert_eq!(normalized.rows[0], duplicate[64]);
}

#[test]
fn all_short_three_key_sequences_and_four_key_seed_orders() {
    for n in 0..=7 {
        for mut code in 0usize..3usize.pow(n) {
            let mut keys = vec![];
            for _ in 0..n {
                keys.push(code % 3);
                code /= 3;
            }
            check_qc(&keys);
            check_tc(&keys);
        }
    }
    for mut code in 0..256 {
        let mut keys = vec![];
        for _ in 0..4 {
            keys.push(code % 4);
            code /= 4;
        }
        check_qc(&keys);
        check_tc(&keys);
    }
}

#[test]
fn larger_runs_and_native_scratch_capacity_transition_sizes() {
    // Sizes straddle the 4096 min-run formula and both native 8,000,000/row-size
    // scratch caps. This tests the logical result, not target allocations.
    for n in [4095, 4096, 4097, 76922, 76923, 76924, 83332, 83333, 83334] {
        let keys: Vec<_> = (0..n).map(|i| (i * 7919 + i / 31) % 1031).collect();
        check_qc(&keys);
        check_tc(&keys);
    }
}

#[test]
fn normalization_is_idempotent_but_reordering_conflicts_changes_winner() {
    let first: QcRow = row(9, 1);
    let last: QcRow = row(9, 2);
    let forward = normalize_qc(&[first.clone(), last.clone()]);
    assert_eq!(forward.rows, vec![last.clone()]);
    assert_eq!(normalize_qc(&forward.rows), forward);
    assert_eq!(normalize_qc(&[last, first.clone()]).rows, vec![first]);
}
