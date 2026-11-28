//! Compare the public base map with retained quantity-map entry decisions.
#[allow(dead_code)]
#[path = "../../../src/node115-base/src/l1_map.rs"]
mod l1_map;

use l1_map::{Entry, L1Map};

fn key(index: u64) -> [u8; 20] {
    let mut bytes = [0; 20];
    bytes[12..].copy_from_slice(&index.to_be_bytes());
    bytes
}

fn main() {
    let mut completed_entries = 0;
    let mut demotion_calls = 0;
    for row in include_str!("entry-cases.tsv").lines().skip(1) {
        let fields: Vec<_> = row.split('\t').collect();
        let size: u64 = fields[2].parse().unwrap();
        let values = (0..size).map(|i| (key(i), i));
        let mut map = if fields[3] == "0x8000000000000000" {
            L1Map::Large(values.collect())
        } else {
            L1Map::Small(values.collect())
        };
        let outcome = fields[4];
        if outcome.starts_with("demote-call") {
            // The retained trace ends at the conversion call. Compare only
            // the decision to leave tree representation on this entry.
            let _ = map.entry(key(size));
            assert!(!map.is_large(), "{row}");
            demotion_calls += 1;
            continue;
        }
        let (presence, shape) = outcome.split_once('/').unwrap();
        let present = presence == "occupied";
        let entry = map.entry(key(if present { 0 } else { size }));
        assert_eq!(matches!(entry, Entry::Occupied(_)), present, "{row}");
        assert_eq!(map.is_large(), shape == "tree", "{row}");
        completed_entries += 1;
    }
    println!("{completed_entries} complete entries, {demotion_calls} demotion calls");
}
