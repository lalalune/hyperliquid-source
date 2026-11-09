use node115_validator_unregister::*;
use std::collections::BTreeMap;

fn key(n: u64) -> Address {
    let mut a = [0x55; 20];
    a[12..].copy_from_slice(&n.to_be_bytes());
    a
}
fn items(s: &str) -> impl Iterator<Item = &str> {
    s.split(';').filter(|x| *x != "-")
}
fn number(s: &str) -> u64 {
    s.parse().unwrap()
}
fn bytes(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks_exact(2)
        .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
        .collect()
}
fn parse(s: &str) -> State {
    let f: Vec<_> = s.split('|').collect();
    let wordmap = |s: &str| -> BTreeMap<Address, Vec<u64>> {
        items(s)
            .map(|x| {
                let (k, v) = x.split_once(':').unwrap();
                (key(number(k)), v.split(',').map(number).collect())
            })
            .collect()
    };
    State {
        blocking_records: wordmap(f[0])
            .into_iter()
            .map(|(k, v)| {
                (
                    k,
                    BlockingRecord {
                        words: v.try_into().unwrap(),
                    },
                )
            })
            .collect(),
        validators: items(f[1])
            .map(|x| {
                let v: Vec<_> = x.split(':').collect();
                (
                    key(number(v[0])),
                    Validator {
                        related_key: key(number(v[1])),
                        payload: bytes(v[2]),
                    },
                )
            })
            .collect(),
        auxiliary: wordmap(f[2])
            .into_iter()
            .map(|(k, v)| (k, v.try_into().unwrap()))
            .collect(),
        timestamps: wordmap(f[3])
            .into_iter()
            .map(|(k, v)| (k, v.try_into().unwrap()))
            .collect(),
        history: items(f[4])
            .map(|x| {
                let (k, p) = x.split_once(':').unwrap();
                HistoryRow {
                    key: number(k),
                    payload: bytes(p),
                }
            })
            .collect(),
        related_keys: items(f[5]).map(|x| key(number(x))).collect(),
        followups: items(f[6])
            .map(|x| {
                let v: Vec<_> = x.split(':').collect();
                (
                    key(number(v[0])),
                    Followup {
                        history_key: number(v[1]),
                        action_key: key(number(v[2])),
                    },
                )
            })
            .collect(),
    }
}
#[test]
fn independent_list_state_sequences() {
    let mut state = State::default();
    let mut actions = 0;
    for line in include_str!("reference.tsv").lines() {
        let v: Vec<_> = line.split('\t').collect();
        if v[0] == "I" {
            state = parse(v[1]);
            continue;
        }
        let result = unregister(&mut state, key(number(v[1])));
        assert_eq!(result as u64, number(v[2]), "status {actions}");
        assert_eq!(state, parse(v[3]), "state {actions}");
        actions += 1;
    }
    assert_eq!(actions, 4000);
}
#[test]
fn blocked_precedes_missing_and_does_not_write() {
    let mut state = State::default();
    state.blocking_records.insert(
        key(1),
        BlockingRecord {
            words: [0, 0, 0, 0, 1],
        },
    );
    state.auxiliary.insert(key(1), [7, 8]);
    state.timestamps.insert(key(1), [1, 2, 3]);
    let before = state.clone();
    assert_eq!(unregister(&mut state, key(1)), Status::Blocked);
    assert_eq!(state, before);
    state.blocking_records.get_mut(&key(1)).unwrap().words[4] = 0;
    let before = state.clone();
    assert_eq!(unregister(&mut state, key(1)), Status::MissingValidator);
    assert_eq!(state, before);
}
#[test]
fn ordered_history_and_same_related_key_replace_followup() {
    let mut state = State {
        history: vec![
            HistoryRow {
                key: 99,
                payload: vec![7],
            },
            HistoryRow {
                key: 3,
                payload: vec![8],
            },
        ],
        ..State::default()
    };
    state.validators.insert(
        key(1),
        Validator {
            related_key: key(9),
            payload: vec![1],
        },
    );
    state.validators.insert(
        key(2),
        Validator {
            related_key: key(9),
            payload: vec![2],
        },
    );
    state.auxiliary.insert(key(1), [7, 8]);
    state.timestamps.insert(key(1), [1, 2, 3]);
    assert_eq!(unregister(&mut state, key(1)), Status::Accepted);
    assert_eq!(
        state.followups[&key(9)],
        Followup {
            history_key: 3,
            action_key: key(1)
        }
    );
    assert!(!state.auxiliary.contains_key(&key(1)));
    assert!(!state.timestamps.contains_key(&key(1)));
    assert_eq!(unregister(&mut state, key(2)), Status::Accepted);
    assert_eq!(
        state.followups[&key(9)],
        Followup {
            history_key: 3,
            action_key: key(2)
        }
    );
    assert_eq!(state.related_keys.len(), 1);
}
#[test]
fn empty_history_zero_and_full_twenty_byte_keys() {
    let mut state = State::default();
    state.blocking_records.insert(
        key(1),
        BlockingRecord {
            words: [u64::MAX; 5],
        },
    );
    state.validators.insert(
        key(2),
        Validator {
            related_key: key(2),
            payload: vec![9],
        },
    );
    assert_eq!(unregister(&mut state, key(2)), Status::Accepted);
    assert_eq!(
        state.followups[&key(2)],
        Followup {
            history_key: 0,
            action_key: key(2)
        }
    );
    assert!(state.blocking_records.contains_key(&key(1)));
}
