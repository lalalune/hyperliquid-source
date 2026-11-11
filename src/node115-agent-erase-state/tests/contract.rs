use node115_agent_erase_state::*;
use std::collections::{BTreeMap, BTreeSet};
fn bytes(s: &str) -> Vec<u8> {
    if s == "-" {
        return vec![];
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn key(s: &str) -> Address {
    bytes(s).try_into().unwrap()
}
fn agents(s: &str) -> BTreeMap<Address, Vec<Agent>> {
    if s == "-" {
        return BTreeMap::new();
    }
    s.split('|')
        .map(|part| {
            let (k, v) = part.split_once('=').unwrap();
            let rows = if v == "-" {
                vec![]
            } else {
                v.split(';')
                    .map(|row| {
                        let p: Vec<_> = row.split(',').collect();
                        Agent {
                            name: String::from_utf8(bytes(p[0])).unwrap(),
                            address: key(p[1]),
                            opaque: bytes(p[2]).try_into().unwrap(),
                        }
                    })
                    .collect()
            };
            (key(k), rows)
        })
        .collect()
}
fn followups(s: &str) -> BTreeMap<Address, BTreeSet<Followup>> {
    if s == "-" {
        return BTreeMap::new();
    }
    s.split('|')
        .map(|part| {
            let (k, v) = part.split_once('=').unwrap();
            let rows = if v == "-" {
                BTreeSet::new()
            } else {
                v.split(';')
                    .map(|row| {
                        let p: Vec<_> = row.split(',').collect();
                        Followup {
                            agent: key(p[0]),
                            at: Moment::new(
                                p[1].parse().unwrap(),
                                p[2].parse().unwrap(),
                                p[3].parse().unwrap(),
                            )
                            .unwrap(),
                        }
                    })
                    .collect()
            };
            (key(k), rows)
        })
        .collect()
}
#[test]
fn independent_sequential_state_reference() {
    let mut count = 0;
    for (i, line) in include_str!("cases.tsv").lines().enumerate() {
        let p: Vec<_> = line.split('\t').collect();
        let mut state = State {
            agents: agents(p[5]),
            followups: followups(p[6]),
        };
        let now = Moment::new(
            p[2].parse().unwrap(),
            p[3].parse().unwrap(),
            p[4].parse().unwrap(),
        )
        .unwrap();
        let name = String::from_utf8(bytes(p[1])).unwrap();
        assert_eq!(
            erase(&mut state, key(p[0]), &name, now),
            p[7].parse::<u16>().unwrap(),
            "case {i}"
        );
        assert_eq!(
            state,
            State {
                agents: agents(p[8]),
                followups: followups(p[9])
            },
            "case {i}"
        );
        count += 1;
    }
    assert_eq!(count, 4000);
}
#[test]
fn missing_owner_is_created_without_followup() {
    let mut s = State::default();
    let now = Moment::new(1, 0, 0).unwrap();
    assert_eq!(erase(&mut s, [7; 20], "", now), 0x5c);
    assert_eq!(s.agents.get(&[7; 20]), Some(&vec![]));
    assert!(s.followups.is_empty());
}
#[test]
fn first_match_replaces_entire_set_and_retains_neighbors() {
    let owner = [9; 20];
    let now = Moment::new(1, 86399, 1_500_000_000).unwrap();
    let a = Agent {
        name: "é\0".into(),
        address: [1; 20],
        opaque: [8; 12],
    };
    let mut b = a.clone();
    b.address[19] = 2;
    let mut s = State::default();
    s.agents.insert(owner, vec![a.clone(), b.clone()]);
    s.followups.insert(
        owner,
        BTreeSet::from([
            Followup {
                agent: [4; 20],
                at: now,
            },
            Followup {
                agent: [5; 20],
                at: now,
            },
        ]),
    );
    assert_eq!(erase(&mut s, owner, "é\0", now), 0x5c);
    assert_eq!(erase(&mut s, owner, "é\0", now), 0x1a2);
    assert_eq!(s.agents[&owner], vec![b]);
    assert_eq!(
        s.followups[&owner],
        BTreeSet::from([Followup {
            agent: a.address,
            at: Moment::new(2, 5, 500_000_000).unwrap()
        }])
    );
}
#[test]
fn calendar_and_leap_boundaries() {
    assert!(Moment::new(-95746130, 0, 0).is_none());
    assert!(Moment::new(95745400, 0, 0).is_none());
    assert!(Moment::new(1, 86400, 0).is_none());
    assert!(Moment::new(1, 58, 1_000_000_000).is_none());
    assert!(Moment::new(1, 59, 2_000_000_000).is_none());
    assert_eq!(
        Moment::new(95745399, 86394, 0).unwrap().after_six_seconds(),
        Moment::MAX
    );
    assert_eq!(
        Moment::new(95745399, 86393, 0)
            .unwrap()
            .after_six_seconds()
            .parts(),
        (95745399, 86399, 0)
    );
    assert_eq!(
        Moment::new(-95746129, 59, 1_999_999_999)
            .unwrap()
            .after_six_seconds()
            .parts(),
        (-95746129, 65, 999_999_999)
    );
}
