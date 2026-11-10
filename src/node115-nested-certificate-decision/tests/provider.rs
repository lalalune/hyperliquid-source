//! Drives `StakeHistory` (the provider `0x595e5c0`) with the frozen corpus `cases-provider.tsv` (expected
//! values from `gen_provider_corpus.py`, fixed before `history.rs` existed; see `ORACLE_FROZEN.txt`).
//! A stored stake set is recognised by its `validator_count`, which the harness sets to the stored round.

use std::collections::BTreeSet;
use std::fs;

use node115_nested_certificate_decision::history::{Rounds, StakeHistory};
use node115_nested_certificate_decision::stake::{StakeMap, StakeSet};

const CORPUS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../research/work-items/RE-008-node115-nested-certificate-decision/cases-provider.tsv"
);

fn u(s: &str) -> u64 {
    u64::from_str_radix(s, 16).unwrap()
}

fn marked(round: u64) -> StakeSet {
    StakeSet { stakes: StakeMap::tree([]), validators: BTreeSet::new(), validator_count: round }
}

fn rounds(s: &str) -> Rounds {
    let (head, body) = s.split_once('=').unwrap();
    let live: Vec<u64> = if body.is_empty() { Vec::new() } else { body.split(',').map(u).collect() };
    if head == "T" {
        return Rounds::tree(live.into_iter().map(|r| (r, marked(r))));
    }
    let (cap, hd) = head[1..].split_once('.').unwrap();
    let (cap, hd): (usize, usize) = (cap.parse().unwrap(), hd.parse().unwrap());
    // Unused capacity rows hold unordered junk: the native search must not depend on them.
    let mut rows: Vec<(u64, StakeSet)> = (0..cap).map(|i| (u64::MAX - i as u64 * 7, marked(0xDEAD))).collect();
    let len = live.len();
    for (i, r) in live.into_iter().enumerate() {
        rows[(hd + i) % cap] = (r, marked(r));
    }
    Rounds::ring(rows, hd, len).expect("increasing ring")
}

#[test]
fn provider_corpus() {
    let text = fs::read_to_string(CORPUS).expect("corpus");
    let (mut total, mut bad) = (0, Vec::new());
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split('\t').collect();
        assert_eq!(f.len(), 9, "{line}");
        total += 1;
        let history = StakeHistory::new(rounds(f[2]), u(f[3]), u(f[4]), u(f[5]));
        let got = history.lookup(u(f[6])).map(|s| format!("{:x}", s.validator_count)).unwrap_or("-".into());
        let counter = format!("{:x}", history.warnings.get());
        if got != f[7] || counter != f[8] {
            bad.push(format!("{} {} got {got} {counter}", f[0], f[1]));
        }
    }
    println!("CORPUS provider cases={} mismatches={}", total, bad.len());
    for b in bad.iter().take(10) {
        println!("MISMATCH {b}");
    }
    assert_eq!(total, 522);
    assert!(bad.is_empty());
}

#[test]
fn ring_constructor_refuses_unordered_or_oversized_views() {
    let row = |r: u64| (r, marked(r));
    assert!(Rounds::ring(vec![row(2), row(1)], 0, 2).is_none());
    assert!(Rounds::ring(vec![row(1), row(1)], 0, 2).is_none());
    assert!(Rounds::ring(vec![row(1)], 0, 2).is_none());
    assert!(Rounds::ring(vec![row(1), row(2)], 2, 1).is_none());
    // Wrapped but increasing along the logical order.
    assert!(Rounds::ring(vec![row(3), row(1), row(2)], 1, 3).is_some());
    assert!(Rounds::ring(Vec::new(), 0, 0).is_some());
}
