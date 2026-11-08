use node115_set_referrer::*;
use std::collections::BTreeMap;
fn old() -> Moment {
    Moment::new(719163, 1, 2).unwrap()
}
#[test]
fn independent_calendar_and_state_reference() {
    let mut count = 0;
    for (case, line) in include_str!("reference.tsv").lines().enumerate() {
        let v: Vec<_> = line.split('\t').collect();
        assert_eq!(v.len(), 19);
        let yes = |i: usize| v[i] == "1";
        let n = |i: usize| v[i].parse::<u64>().unwrap();
        let now = Moment::new(
            v[9].parse().unwrap(),
            v[10].parse().unwrap(),
            v[11].parse().unwrap(),
        )
        .unwrap();
        let user = [1; 20];
        let referrer = [2; 20];
        let other = [3; 20];
        let mut state = State {
            period_millis: n(5),
            ..State::default()
        };
        state.codes.insert("untouched".into(), [9; 20]);
        state.users.insert(
            [9; 20],
            User {
                referrer: Some(other),
            },
        );
        if yes(0) {
            state.users.insert(
                user,
                User {
                    referrer: yes(1).then_some(other),
                },
            );
        }
        if yes(2) {
            state
                .codes
                .insert("CODE-é".into(), if yes(3) { user } else { referrer });
        }
        if yes(4) {
            let mut history = BTreeMap::from([([9; 20], old())]);
            if yes(12) {
                history.insert(user, old());
            }
            state.referrers.insert(
                referrer,
                Referrer {
                    history,
                    remaining: n(7),
                    bucket: n(6),
                    configured_quota: n(8),
                },
            );
        }
        let mut expected = state.clone();
        if yes(14) {
            expected.users.insert(
                user,
                User {
                    referrer: match v[15] {
                        "0" => None,
                        "1" => Some(other),
                        "2" => Some(referrer),
                        _ => panic!(),
                    },
                },
            );
        }
        if let Some(record) = expected.referrers.get_mut(&referrer) {
            record.bucket = n(16);
            record.remaining = n(17);
            if yes(18) {
                record.history.insert(user, now);
            }
        }
        let status = set_referrer(&mut state, user, "CODE-é", now);
        assert_eq!(
            status as u16,
            v[13].parse::<u16>().unwrap(),
            "status case{case}"
        );
        assert_eq!(state, expected, "state case{case}");
        count += 1;
    }
    assert_eq!(count, 8000);
}
fn state() -> State {
    State {
        codes: BTreeMap::from([("Code".into(), [2; 20])]),
        users: BTreeMap::new(),
        referrers: BTreeMap::from([(
            [2; 20],
            Referrer {
                history: BTreeMap::new(),
                remaining: 0,
                bucket: 0,
                configured_quota: 0,
            },
        )]),
        period_millis: 1000,
    }
}
#[test]
fn mutation_and_gate_order() {
    let now = Moment::new(719163, 1, 0).unwrap();
    let mut s = state();
    assert_eq!(
        set_referrer(&mut s, [1; 20], "code", now),
        Status::MissingCode
    );
    assert!(s.users.is_empty());
    assert_eq!(
        set_referrer(&mut s, [2; 20], "Code", now),
        Status::SelfReferral
    );
    assert!(s.users.is_empty());
    s.referrers.clear();
    assert_eq!(set_referrer(&mut s, [1; 20], "Code", now), Status::Accepted);
    assert_eq!(s.users[&[1; 20]].referrer, None);
    let mut s = state();
    assert_eq!(set_referrer(&mut s, [1; 20], "Code", now), Status::Accepted);
    assert_eq!(s.referrers[&[2; 20]].remaining, 999);
    s.period_millis = 0;
    assert_eq!(
        set_referrer(&mut s, [1; 20], "Code", now),
        Status::AlreadySet
    );
    assert_eq!(
        set_referrer(&mut s, [4; 20], "Code", now),
        Status::QuotaExceeded
    );
    assert!(s.users.contains_key(&[4; 20]));
    assert_eq!(s.users[&[4; 20]].referrer, None);
}
#[test]
fn pre_epoch_clamp_and_existing_history_replacement() {
    let mut s = state();
    s.referrers.get_mut(&[2; 20]).unwrap().remaining = 1;
    s.referrers
        .get_mut(&[2; 20])
        .unwrap()
        .history
        .insert([1; 20], old());
    let now = Moment::new(1, 0, 0).unwrap();
    assert_eq!(set_referrer(&mut s, [1; 20], "Code", now), Status::Accepted);
    assert_eq!(s.referrers[&[2; 20]].bucket, 0);
    assert_eq!(s.referrers[&[2; 20]].remaining, 0);
    assert_eq!(s.referrers[&[2; 20]].history[&[1; 20]], now);
    assert_eq!(
        set_referrer(&mut s, [3; 20], "Code", now),
        Status::QuotaExceeded
    );
}
#[test]
fn owned_moment_domain() {
    assert!(Moment::new(i32::MAX, 0, 0).is_none());
    assert!(Moment::new(i32::MIN, 0, 0).is_none());
    assert!(Moment::new(719163, 86400, 0).is_none());
    assert!(Moment::new(719163, 0, 1_000_000_000).is_none());
    assert_eq!(old().parts(), (719163, 1, 2));
}
