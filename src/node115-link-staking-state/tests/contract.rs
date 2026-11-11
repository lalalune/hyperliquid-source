use node115_link_staking_state::{Error, Link, Outcome, State, apply};

#[test]
fn request_gates_and_finalize() {
    let a = [1; 20];
    let b = [2; 20];
    let mut s = State::default();
    assert_eq!(
        apply(&mut s, a, a, 0),
        Outcome::Rejected(Error::NoStakedKey)
    );
    s.staked.insert(a);
    assert_eq!(apply(&mut s, a, a, 0), Outcome::Rejected(Error::SameKey));
    assert_eq!(
        apply(&mut s, b, a, 1),
        Outcome::Rejected(Error::PendingRequestRequired)
    );
    assert_eq!(apply(&mut s, a, b, 0), Outcome::Accepted);
    assert_eq!(s.links[&b], Link { tag: 0, peer: a });
    assert_eq!(apply(&mut s, b, a, 255), Outcome::Accepted);
    assert_eq!(s.links[&b], Link { tag: 1, peer: a });
    assert_eq!(s.links[&a], Link { tag: 2, peer: b });
}

#[test]
fn ordering_and_same_key_finalize() {
    let a = [1; 20];
    let b = [2; 20];
    let mut s = State::default();
    s.staked.insert(a);
    s.links.insert(b, Link { tag: 3, peer: a });
    s.links.insert(a, Link { tag: 4, peer: b });
    let old = s.clone();
    assert_eq!(
        apply(&mut s, a, b, 0),
        Outcome::Rejected(Error::TradingAlreadyLinked)
    );
    assert_eq!(s, old);
    s.links.insert(b, Link { tag: 0, peer: a });
    assert_eq!(
        apply(&mut s, b, a, 1),
        Outcome::Rejected(Error::StakingAlreadyLinked)
    );
    let mut s = State::default();
    s.links.insert(a, Link { tag: 0, peer: a });
    assert_eq!(apply(&mut s, a, a, 1), Outcome::Accepted);
    assert_eq!(s.links[&a], Link { tag: 2, peer: a });
}

#[test]
fn selected_state_cross_product() {
    let a = [1; 20];
    let b = [2; 20];
    let other = [3; 20];
    for staked in [false, true] {
        for first in [
            None,
            Some(Link { tag: 0, peer: a }),
            Some(Link { tag: 1, peer: a }),
            Some(Link {
                tag: 2,
                peer: other,
            }),
        ] {
            for second in [
                None,
                Some(Link { tag: 0, peer: a }),
                Some(Link { tag: 1, peer: a }),
                Some(Link {
                    tag: 2,
                    peer: other,
                }),
            ] {
                for mode in [0, 1, 2, 255] {
                    let mut s = State::default();
                    if staked {
                        s.staked.insert(a);
                    }
                    if let Some(v) = first {
                        s.links.insert(a, v);
                    }
                    if let Some(v) = second {
                        s.links.insert(b, v);
                    }
                    let before = s.clone();
                    let out = if mode == 0 {
                        apply(&mut s, a, b, mode)
                    } else {
                        apply(&mut s, b, a, mode)
                    };
                    let expected = if mode == 0 {
                        if !staked {
                            Outcome::Rejected(Error::NoStakedKey)
                        } else if second.is_some_and(|v| v.tag != 0) {
                            Outcome::Rejected(Error::TradingAlreadyLinked)
                        } else if first.is_some_and(|v| v.tag != 0) {
                            Outcome::Rejected(Error::StakingAlreadyLinked)
                        } else {
                            Outcome::Accepted
                        }
                    } else if !second.is_some_and(|v| v.tag == 0 && v.peer == a) {
                        Outcome::Rejected(Error::PendingRequestRequired)
                    } else if first.is_some_and(|v| v.tag != 0) {
                        Outcome::Rejected(Error::StakingAlreadyLinked)
                    } else {
                        Outcome::Accepted
                    };
                    assert_eq!(out, expected);
                    if out != Outcome::Accepted {
                        assert_eq!(s, before);
                    } else if mode == 0 {
                        assert_eq!(s.links[&b], Link { tag: 0, peer: a });
                    } else {
                        assert_eq!(s.links[&a], Link { tag: 2, peer: b });
                        assert_eq!(s.links[&b], Link { tag: 1, peer: a });
                    }
                }
            }
        }
    }
}

#[test]
fn independent_list_reference_sequences() {
    let mut state = State::default();
    let mut scenario = u32::MAX;
    for line in include_str!("reference-vectors.txt").lines() {
        let mut f = line.split_whitespace();
        let s: u32 = f.next().unwrap().parse().unwrap();
        let p: u8 = f.next().unwrap().parse().unwrap();
        let c: u8 = f.next().unwrap().parse().unwrap();
        let mode: u8 = f.next().unwrap().parse().unwrap();
        let expected: u8 = f.next().unwrap().parse().unwrap();
        let staked = f.next().unwrap();
        let entries = f.next().unwrap();
        if s != scenario {
            state = State::default();
            if staked != "-" {
                for item in staked.split(',') {
                    state.staked.insert([item.parse().unwrap(); 20]);
                }
            }
            scenario = s;
        }
        let got = apply(&mut state, [p; 20], [c; 20], mode);
        let code = match got {
            Outcome::Accepted => 0,
            Outcome::Rejected(Error::NoStakedKey) => 1,
            Outcome::Rejected(Error::SameKey) => 2,
            Outcome::Rejected(Error::TradingAlreadyLinked) => 3,
            Outcome::Rejected(Error::StakingAlreadyLinked) => 4,
            Outcome::Rejected(Error::PendingRequestRequired) => 5,
        };
        assert_eq!(code, expected);
        let mut expected_links = std::collections::BTreeMap::new();
        if entries != "-" {
            for row in entries.split(',') {
                let v: Vec<u8> = row.split(':').map(|n| n.parse().unwrap()).collect();
                expected_links.insert(
                    [v[0]; 20],
                    Link {
                        tag: v[1],
                        peer: [v[2]; 20],
                    },
                );
            }
        }
        assert_eq!(state.links, expected_links);
    }
}
