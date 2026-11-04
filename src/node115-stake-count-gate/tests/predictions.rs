use node115_stake_count_gate::{evaluate, Key};
use std::collections::{BTreeMap, BTreeSet};

fn key(alias: &str) -> Key {
    assert_eq!(alias.len(), 1);
    let mut bytes = [0; 20];
    bytes[19] = alias.as_bytes()[0];
    bytes
}

fn keys(source: &str) -> Vec<Key> {
    if source.is_empty() {
        Vec::new()
    } else {
        source.split(',').map(key).collect()
    }
}

#[test]
fn frozen_preimplementation_predictions() {
    let table = include_str!(
        "../../../research/work-items/RE-008-node115-stake-count-gate/predictions.tsv"
    );
    for row in table.lines().skip(1) {
        let fields: Vec<_> = row.split('\t').collect();
        assert_eq!(fields.len(), 7);
        let first = keys(fields[1]);
        let second = keys(fields[2]);
        let weights: BTreeMap<_, _> = if fields[3].is_empty() {
            BTreeMap::new()
        } else {
            fields[3]
                .split(',')
                .map(|item| {
                    let (alias, value) = item.split_once(':').expect("weight pair");
                    (key(alias), value.parse::<u64>().expect("unsigned weight"))
                })
                .collect()
        };
        let fraction = f64::from_bits(u64::from_str_radix(fields[4], 16).expect("f64 bits"));
        let members: BTreeSet<_> = keys(fields[5]).into_iter().collect();
        assert_eq!(
            evaluate(&first, &second, &weights, fraction, &members),
            fields[6] == "1",
            "frozen native-derived prediction {}",
            fields[0]
        );
    }
}
