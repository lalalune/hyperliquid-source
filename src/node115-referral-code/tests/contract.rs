use node115_referral_code::*;
use std::collections::BTreeMap;
fn key(n: u64) -> Address {
    let mut a = [0; 20];
    a[12..].copy_from_slice(&n.to_be_bytes());
    a
}
fn string(s: &str) -> String {
    if s == "-" {
        return String::new();
    }
    let bytes: Vec<u8> = s
        .as_bytes()
        .chunks_exact(2)
        .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
        .collect();
    String::from_utf8(bytes).unwrap()
}
fn records(s: &str) -> BTreeMap<Address, Referrer> {
    if s == "-" {
        return BTreeMap::new();
    }
    s.split(';')
        .map(|row| {
            let v: Vec<_> = row.split(',').collect();
            (
                key(v[0].parse().unwrap()),
                Referrer {
                    code: string(v[1]),
                    remaining: v[2].parse().unwrap(),
                    bucket: v[3].parse().unwrap(),
                    configured_quota: v[4].parse().unwrap(),
                    history: if v[5] == "1" {
                        BTreeMap::from([(key(99), [123, 456, 789])])
                    } else {
                        BTreeMap::new()
                    },
                },
            )
        })
        .collect()
}
fn codes(s: &str) -> BTreeMap<String, Address> {
    if s == "-" {
        return BTreeMap::new();
    }
    s.split(';')
        .map(|x| {
            let (a, b) = x.split_once(',').unwrap();
            (string(a), key(b.parse().unwrap()))
        })
        .collect()
}
#[test]
fn independent_state_sequences() {
    let mut state = State::default();
    let mut actions = 0;
    for line in include_str!("reference.tsv").lines() {
        let v: Vec<_> = line.split('\t').collect();
        if v[0] == "I" {
            state = State {
                referrers: records(v[2]),
                codes: codes(v[3]),
                ..State::default()
            };
            if v[1] != "-" {
                for x in v[1].split(';') {
                    let (u, values) = x.split_once(':').unwrap();
                    state.volume_rows.insert(
                        key(u.parse().unwrap()),
                        values
                            .split(',')
                            .enumerate()
                            .map(|(i, n)| (i as u64 * 10000, n.parse().unwrap()))
                            .collect(),
                    );
                }
            }
            continue;
        }
        let user = key(v[2].parse().unwrap());
        let code = string(v[3]);
        let before_volumes = state.volume_rows.clone();
        let expected: u16 = v[6].parse().unwrap();
        if v[1] == "2" {
            let reply = register(&mut state, user, &code);
            assert_eq!(
                reply.tag,
                v[5].parse::<u8>().unwrap(),
                "tag action{actions}"
            );
            assert_eq!(
                reply.error,
                if expected == 0x1a2 {
                    None
                } else {
                    Some(expected)
                },
                "wrapper action{actions}"
            );
        } else {
            let mode = if v[1] == "0" {
                Mode::Register
            } else {
                Mode::Modify
            };
            assert_eq!(
                apply(&mut state, user, &code, v[4].parse().unwrap(), mode) as u16,
                expected,
                "core action{actions}"
            );
        }
        assert_eq!(state.referrers, records(v[7]), "records action{actions}");
        assert_eq!(state.codes, codes(v[8]), "codes action{actions}");
        assert_eq!(state.volume_rows, before_volumes);
        actions += 1;
    }
    assert_eq!(actions, 4000);
}
#[test]
fn volume_and_length_precedence_in_core_and_wrapper() {
    let mut s = State::default();
    let user = key(1);
    let long = "x".repeat(101);
    assert_eq!(
        apply(&mut s, user, &long, 0, Mode::Register),
        Status::InsufficientVolume
    );
    assert_eq!(
        apply(&mut s, user, &long, 0, Mode::Modify),
        Status::CodeTooLong
    );
    assert_eq!(
        register(&mut s, user, &long),
        RegistrationReply {
            tag: 15,
            error: Some(0x158)
        }
    );
    assert!(s.referrers.is_empty());
    s.volume_rows
        .insert(user, BTreeMap::from([(0, 999999), (10000, 1)]));
    assert_eq!(
        register(&mut s, user, ""),
        RegistrationReply {
            tag: 14,
            error: None
        }
    );
    assert_eq!(s.codes[""], user);
    assert_eq!(s.referrers[&user].configured_quota, 0);
}
#[test]
fn same_owner_modification_preserves_history_and_remaining() {
    let user = key(1);
    let mut s = State::default();
    s.volume_rows
        .insert(user, BTreeMap::from([(0, u64::MAX), (1, 1)]));
    assert_eq!(
        apply(&mut s, user, "old", 8, Mode::Register),
        Status::Accepted
    );
    let r = s.referrers.get_mut(&user).unwrap();
    r.remaining = 42;
    r.bucket = 999;
    r.history.insert(key(2), [1, 2, 3]);
    s.codes.insert("alias".into(), user);
    assert_eq!(
        apply(&mut s, user, "alias", 11, Mode::Modify),
        Status::Accepted
    );
    assert!(!s.codes.contains_key("old"));
    assert_eq!(s.codes["alias"], user);
    let r = &s.referrers[&user];
    assert_eq!((r.remaining, r.bucket, r.configured_quota), (42, 0, 11));
    assert_eq!(r.history[&key(2)], [1, 2, 3]);
    let before = s.clone();
    s.codes.insert("other".into(), key(3));
    let blocked = s.clone();
    assert_eq!(
        apply(&mut s, user, "other", 0, Mode::Modify),
        Status::CodeTaken
    );
    assert_eq!(s, blocked);
    assert_eq!(before.referrers[&user].code, "alias");
}
#[test]
fn occupied_code_is_rejected_for_absent_record_even_same_owner() {
    let user = key(1);
    let mut s = State::default();
    s.codes.insert("same".into(), user);
    assert_eq!(
        apply(&mut s, user, "same", 0, Mode::Modify),
        Status::CodeTaken
    );
    assert!(s.referrers.is_empty());
    assert_eq!(
        apply(
            &mut s,
            user,
            "é".repeat(50).as_str(),
            u64::MAX,
            Mode::Modify
        ),
        Status::Accepted
    );
}
