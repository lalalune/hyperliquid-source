use node115_fee_trial::*;
use std::collections::BTreeMap;
fn key(n: u64) -> Address {
    if n == 250 {
        return [0xff; 20];
    }
    if n == 251 {
        return [0xfe; 20];
    }
    let mut a = [0x77; 20];
    a[12..].copy_from_slice(&n.to_be_bytes());
    a
}
fn date(s: &str) -> Option<Date> {
    if s == "n" {
        None
    } else {
        Some(Date::from_ce_days(s.parse().unwrap()).unwrap())
    }
}
fn n(s: &str) -> u64 {
    s.parse().unwrap()
}
fn f(s: &str) -> f64 {
    f64::from_bits(u64::from_str_radix(s, 16).unwrap())
}
fn fs<const N: usize>(s: &str) -> [f64; N] {
    s.split(',').map(f).collect::<Vec<_>>().try_into().unwrap()
}
fn rows<const N: usize>(s: &str) -> Vec<[f64; N]> {
    if s == "~" {
        vec![]
    } else {
        s.split(';').map(fs).collect()
    }
}
fn users(s: &str) -> BTreeMap<Address, User> {
    if s == "~" {
        return BTreeMap::new();
    }
    s.split(';')
        .map(|row| {
            let v: Vec<_> = row.split(':').collect();
            let custom = if v[2] == "n" {
                None
            } else {
                let a: Vec<_> = v[2].split(',').collect();
                Some(Trial {
                    active: core::array::from_fn(|i| f(a[i])),
                    volume: f(a[4]),
                    requested: core::array::from_fn(|i| f(a[5 + i])),
                    original: core::array::from_fn(|i| f(a[9 + i])),
                    end: date(a[13]),
                    tail: f(a[14]),
                })
            };
            (
                key(n(v[0])),
                User {
                    last_trial: date(v[1]),
                    custom,
                },
            )
        })
        .collect()
}
fn assert_users(actual: &BTreeMap<Address, User>, expected: &BTreeMap<Address, User>) {
    assert_eq!(actual, expected);
    for (key, user) in actual {
        if let Some(a) = &user.custom {
            let b = expected[key].custom.as_ref().unwrap();
            let all = |t: &Trial| {
                let mut v = t.active.to_vec();
                v.push(t.volume);
                v.extend(t.requested);
                v.extend(t.original);
                v.push(t.tail);
                v.into_iter().map(f64::to_bits).collect::<Vec<_>>()
            };
            assert_eq!(all(a), all(b));
        }
    }
}
#[test]
fn decimal_reference_bit_patterns() {
    let mut count = 0;
    for line in include_str!("decimals.tsv").lines() {
        let (s, b) = line.split_once('\t').unwrap();
        assert_eq!(short_decimal(s).unwrap().to_bits(), f(b).to_bits(), "{s}");
        count += 1;
    }
    assert_eq!(count, 16000);
}
#[test]
fn independent_state_reference() {
    let mut count = 0;
    for line in include_str!("states.tsv").lines() {
        let v: Vec<_> = line.split('\t').collect();
        let mut s = State {
            disabled: v[2].parse().unwrap(),
            default_rates: fs(v[3]),
            templates: rows(v[4]),
            alternatives: rows(v[5]),
            discounts: rows(v[6]),
            users: users(v[7]),
        };
        let before = s.clone();
        let fees: Vec<_> = v[8].split(',').collect();
        let affiliates: Vec<_> = if v[9] == "~" {
            vec![]
        } else {
            v[9].split(',').map(|x| key(n(x))).collect()
        };
        let expected = if v[10] == "overflow" {
            Outcome::DateOverflow
        } else {
            Outcome::Status(v[10].parse().unwrap())
        };
        assert_eq!(
            start(
                &mut s,
                key(n(v[1])),
                date(v[0]).unwrap(),
                fees.try_into().unwrap(),
                &affiliates
            ),
            expected,
            "case {count}"
        );
        assert_users(&s.users, &users(v[11]));
        let mut unchanged = before;
        unchanged.users = s.users.clone();
        assert_eq!(s, unchanged);
        count += 1;
    }
    assert_eq!(count, 4500);
}
fn state() -> State {
    State {
        disabled: 0,
        default_rates: [1.; 4],
        templates: vec![[0.; 4]],
        alternatives: vec![],
        discounts: vec![],
        users: BTreeMap::new(),
    }
}
#[test]
fn parsing_scope_and_error_order() {
    let mut s = state();
    let now = Date::from_ce_days(719163).unwrap();
    let long = "1".repeat(101);
    assert_eq!(
        start(&mut s, key(1), now, [&long, "0", "0", "0"], &[]),
        Outcome::Status(0x158)
    );
    assert_eq!(
        start(&mut s, key(1), now, ["1e-3", &long, "0", "0"], &[]),
        Outcome::UnsupportedString { field: 0 }
    );
    s.disabled = 1;
    assert_eq!(
        start(&mut s, key(1), now, [&long; 4], &[]),
        Outcome::Status(0x14d)
    );
    for text in ["", ".1", "nan", " 1", "1_0", "123456789012345678"] {
        assert!(short_decimal(text).is_none());
    }
    assert_eq!(short_decimal("-0.00").unwrap().to_bits(), 0);
}
#[test]
fn alternative_tier_requires_matching_primary_pair() {
    let now = Date::from_ce_days(719163).unwrap();
    let mut s = state();
    s.templates = vec![[0., 5., 0., 6.]];
    s.alternatives = vec![[999., 0.]];
    assert_eq!(
        start(&mut s, key(1), now, ["0"; 4], &[]),
        Outcome::Status(0x1a2)
    );
    let mut other = state();
    other.templates = vec![[1., 5., 0., 6.]];
    other.alternatives = s.alternatives;
    assert_eq!(
        start(&mut other, key(1), now, ["0"; 4], &[]),
        Outcome::Status(0x14a)
    );
}
#[test]
fn ninety_day_boundary_and_affiliate_override() {
    let mut s = state();
    let now = Date::from_ce_days(719163).unwrap();
    let last = Date::from_ce_days(719073).unwrap();
    s.users.insert(
        key(1),
        User {
            custom: None,
            last_trial: Some(last),
        },
    );
    s.users.insert(
        key(2),
        User {
            custom: None,
            last_trial: Some(now),
        },
    );
    assert_eq!(
        start(&mut s, key(1), now, ["0"; 4], &[key(2), key(2), key(1)]),
        Outcome::Status(0x1a2)
    );
    assert_eq!(s.users[&key(1)].custom, s.users[&key(2)].custom);
    assert_eq!(s.users[&key(1)].last_trial, Some(last));
    assert_eq!(s.users[&key(2)].last_trial, Some(now));
    assert_eq!(
        s.users[&key(1)]
            .custom
            .as_ref()
            .unwrap()
            .end
            .unwrap()
            .ce_days(),
        719177
    );
    assert_eq!(
        start(&mut s, key(1), now, ["0"; 4], &[]),
        Outcome::Status(0x149)
    );
}
#[test]
fn overflow_precedes_no_improvement_and_special_key_ignores_custom() {
    let mut s = state();
    s.default_rates = [0.; 4];
    let max = Date::from_ce_days(95745399).unwrap();
    assert_eq!(
        start(&mut s, key(1), max, ["0"; 4], &[]),
        Outcome::DateOverflow
    );
    let now = Date::from_ce_days(719163).unwrap();
    s.templates = vec![[-1.; 4]];
    s.users.insert(
        key(250),
        User {
            custom: Some(Trial {
                active: [9.; 4],
                volume: 77.,
                requested: [1.; 4],
                original: [2.; 4],
                end: Some(now),
                tail: 5.,
            }),
            last_trial: None,
        },
    );
    assert_eq!(
        start(&mut s, key(250), now, ["-1"; 4], &[]),
        Outcome::Status(0x1a2)
    );
    let t = s.users[&key(250)].custom.as_ref().unwrap();
    assert_eq!(t.original, [0.; 4]);
    assert_eq!((t.volume, t.tail), (0., 0.));
}
