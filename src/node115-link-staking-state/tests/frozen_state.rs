use node115_link_staking_state::{Key, Mode, Relation, RelationKind, Write, apply};
use std::collections::{BTreeMap, BTreeSet};

fn key(s: &str) -> Key {
    assert_eq!(s.len(), 40);
    let mut out = [0; 20];
    for (i, pair) in s.as_bytes().chunks_exact(2).enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap();
    }
    out
}

fn entries(s: &str) -> Vec<Write> {
    if s == "-" {
        return Vec::new();
    }
    s.split(',')
        .map(|row| {
            let fields: Vec<_> = row.split(':').collect();
            assert_eq!(fields.len(), 3);
            let kind = match fields[1] {
                "0" => RelationKind::Pending,
                "1" => RelationKind::TradingLinked,
                "2" => RelationKind::StakingLinked,
                _ => panic!("unestablished stable row tag"),
            };
            Write {
                key: key(fields[0]),
                relation: Relation {
                    kind,
                    peer: key(fields[2]),
                },
            }
        })
        .collect()
}

fn map(s: &str) -> BTreeMap<Key, Relation> {
    let mut m = BTreeMap::new();
    for write in entries(s) {
        assert!(m.insert(write.key, write.relation).is_none());
    }
    m
}

#[test]
fn frozen_whole_state_transitions() {
    let data =
        include_str!("../../../research/work-items/RE-010-link-staking-state-115/frozen-cases.tsv");
    let messages: Vec<_> =
        include_str!("../../../research/work-items/RE-010-link-staking-state-115/messages.tsv")
            .lines()
            .collect();
    assert_eq!(messages.len(), 5);
    let mut count = 0;
    let mut outcomes = [0usize; 6];
    for line in data.lines().filter(|line| !line.starts_with('#')) {
        let c: Vec<_> = line.split('\t').collect();
        assert_eq!(c.len(), 11);
        let mode = match c[1] {
            "0" => Mode::Request,
            "1" => Mode::Finalize,
            _ => panic!("unknown logical mode"),
        };
        let stakes: BTreeSet<Key> = if c[4] == "-" {
            BTreeSet::new()
        } else {
            c[4].split(',').map(key).collect()
        };
        let mut state = map(c[5]);
        // Only real inputs enter the implementation; expectations stay here.
        let outcome = apply(mode, key(c[2]), key(c[3]), &stakes, &mut state);
        let expected_code: u8 = c[6].parse().unwrap();
        assert_eq!(outcome.code(), expected_code, "{} result", c[0]);
        if let Err(error) = outcome.result {
            assert_eq!(
                error.message(),
                messages[usize::from(expected_code - 1)],
                "{} native error text",
                c[0]
            );
        }
        assert_eq!(outcome.writes, entries(c[7]), "{} write order", c[0]);
        assert_eq!(state, map(c[8]), "{} complete state", c[0]);
        assert_eq!(
            outcome.observed_tags(),
            (c[9].parse().unwrap(), c[10].parse().unwrap()),
            "{} active result tags",
            c[0]
        );
        outcomes[usize::from(outcome.code())] += 1;
        count += 1;
    }
    assert_eq!(count, 274);
    assert!(outcomes.into_iter().all(|n| n > 0));
}
