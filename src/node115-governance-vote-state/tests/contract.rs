use node115_governance_vote_state::{AmountRow, Cursor, Proposal, State, Status, Vote, vote};
use std::collections::BTreeMap;

fn c(a: i32, b: u32, d: u32) -> Cursor {
    Cursor {
        first: a,
        second: b,
        third: d,
    }
}
fn initial() -> State {
    let mut s = State::default();
    s.proposals.insert(
        [1; 32],
        Proposal {
            cursor: c(4, 10, 20),
            votes: BTreeMap::new(),
        },
    );
    s.amount_rows.insert(
        [2; 20],
        vec![
            AmountRow {
                amount: 3,
                cursor: c(1, 0, 0),
            },
            AmountRow {
                amount: 5,
                cursor: c(9, 0, 0),
            },
        ],
    );
    s
}

#[test]
fn failures_precede_writes() {
    let mut s = initial();
    let old = s.clone();
    assert_eq!(
        vote(&mut s, [9; 32], [2; 20], 7, c(1, 0, 0)),
        Status::MissingProposal
    );
    assert_eq!(s, old);
    assert_eq!(
        vote(&mut s, [1; 32], [2; 20], 7, c(5, 0, 0)),
        Status::TooLate
    );
    assert_eq!(s, old);
    s.proposals.get_mut(&[1; 32]).unwrap().votes.insert(
        [2; 20],
        Vote {
            amount: 1,
            choice: 0,
        },
    );
    let old = s.clone();
    assert_eq!(
        vote(&mut s, [1; 32], [2; 20], 7, c(4, 10, 20)),
        Status::Duplicate
    );
    assert_eq!(s, old);
}

#[test]
fn accepted_updates_history_and_marker() {
    let mut s = initial();
    s.markers.insert([2; 20], c(5, 0, 0));
    assert_eq!(
        vote(&mut s, [1; 32], [2; 20], 7, c(4, 10, 20)),
        Status::Accepted
    );
    assert_eq!(
        s.proposals[&[1; 32]].votes[&[2; 20]],
        Vote {
            amount: 32,
            choice: 7
        }
    );
    assert_eq!(s.amount_rows[&[2; 20]][0].cursor, c(4, 10, 20));
    assert_eq!(s.amount_rows[&[2; 20]][1].cursor, c(9, 0, 0));
    assert_eq!(s.markers[&[2; 20]], c(5, 0, 0));
}

#[test]
fn amount_overflow_and_shift_cutoff() {
    let mut s = initial();
    s.amount_rows.get_mut(&[2; 20]).unwrap()[0].amount = u64::MAX;
    let old = s.clone();
    assert_eq!(
        vote(&mut s, [1; 32], [2; 20], 0, c(1, 0, 0)),
        Status::ZeroAmount
    );
    assert_eq!(s, old);
    let mut s = initial();
    s.amount_rows.get_mut(&[2; 20]).unwrap().truncate(1);
    s.amount_rows.get_mut(&[2; 20]).unwrap()[0].amount = 1 << 62;
    s.markers.insert([2; 20], c(3, 0, 0));
    assert_eq!(
        vote(&mut s, [1; 32], [2; 20], 1, c(1, 0, 0)),
        Status::Accepted
    );
    assert_eq!(s.proposals[&[1; 32]].votes[&[2; 20]].amount, 1 << 62);
    let mut s = initial();
    s.markers.insert([2; 20], c(4, 10, 20));
    assert_eq!(
        vote(&mut s, [1; 32], [2; 20], 1, c(4, 10, 20)),
        Status::Accepted
    );
    assert_eq!(s.markers[&[2; 20]].first, 0);
}

#[test]
fn independent_integer_reference() {
    for line in include_str!("reference-vectors.txt").lines() {
        let f: Vec<i128> = line
            .split_whitespace()
            .map(|v| v.parse().unwrap())
            .collect();
        let end = c(f[2] as i32, f[3] as u32, f[4] as u32);
        let now = c(f[5] as i32, f[6] as u32, f[7] as u32);
        let marker = c(f[9] as i32, f[10] as u32, f[11] as u32);
        let mut state = State::default();
        if f[0] != 0 {
            let mut p = Proposal {
                cursor: end,
                votes: BTreeMap::new(),
            };
            if f[1] != 0 {
                p.votes.insert(
                    [2; 20],
                    Vote {
                        amount: 4,
                        choice: 9,
                    },
                );
            }
            state.proposals.insert([1; 32], p);
        }
        state.amount_rows.insert(
            [2; 20],
            vec![
                AmountRow {
                    amount: f[12] as u64,
                    cursor: c(-3, 0, 0),
                },
                AmountRow {
                    amount: f[13] as u64,
                    cursor: c(3, 0, 0),
                },
            ],
        );
        if f[8] != 0 {
            state.markers.insert([2; 20], marker);
        }
        let before = state.clone();
        let result = vote(&mut state, [1; 32], [2; 20], 3, now);
        assert_eq!(result as u16, f[14] as u16);
        if result != Status::Accepted {
            assert_eq!(state, before);
        } else {
            assert_eq!(
                state.proposals[&[1; 32]].votes[&[2; 20]],
                Vote {
                    amount: f[15] as u64,
                    choice: 3
                }
            );
            assert_eq!(state.amount_rows[&[2; 20]][0].cursor, c(-3, 0, 0).max(end));
            assert_eq!(state.amount_rows[&[2; 20]][1].cursor, c(3, 0, 0).max(end));
            if f[8] != 0 {
                assert_eq!(state.markers[&[2; 20]].first, f[16] as i32);
            }
        }
    }
}

#[test]
fn full_key_bytes_and_marker_payload() {
    for i in 0..32 {
        let mut key = [1; 32];
        key[i] ^= 1;
        let mut state = initial();
        let before = state.clone();
        assert_eq!(
            vote(&mut state, key, [2; 20], 0, c(1, 0, 0)),
            Status::MissingProposal
        );
        assert_eq!(state, before);
    }
    for i in 0..20 {
        let mut voter = [2; 20];
        voter[i] ^= 1;
        let mut state = initial();
        let before = state.clone();
        assert_eq!(
            vote(&mut state, [1; 32], voter, 0, c(1, 0, 0)),
            Status::ZeroAmount
        );
        assert_eq!(state, before);
    }
    let mut state = initial();
    state.markers.insert([2; 20], c(4, 10, 20));
    assert_eq!(
        vote(&mut state, [1; 32], [2; 20], 0, c(4, 10, 20)),
        Status::Accepted
    );
    assert_eq!(state.markers[&[2; 20]], c(0, 10, 20));
}
