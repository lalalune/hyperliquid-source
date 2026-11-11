use node115_validator_snapshot_publication::*;
use std::{collections::BTreeMap, num::NonZeroU64};

fn moment(year: i32, ordinal: i32, seconds: u32) -> Moment {
    Moment {
        packed_date: (year << 13) | (ordinal << 4) | 7,
        seconds,
        nanos: 17,
    }
}
fn members(count: u8) -> Members<Vec<u8>> {
    (0..count)
        .map(|i| {
            (
                [i; 32],
                Member {
                    signer: [i + 10; 20],
                    other: vec![i; 73],
                },
            )
        })
        .collect()
}
fn store() -> Store<Vec<u8>> {
    Store {
        history: BTreeMap::new(),
        active: members(2),
        moment: moment(1970, 1, 0),
        period: NonZeroU64::new(10).unwrap(),
        selected_epoch: 5,
        next_epoch: 8,
    }
}

#[test]
fn independent_calendar_anchors_and_pre_unix_clamp() {
    let unit = NonZeroU64::new(1).unwrap();
    for (y, d, seconds) in [
        (1970, 1, 0),
        (1970, 2, 86_400),
        (1972, 60, 68_169_600),
        (2000, 60, 951_782_400),
        (2000, 61, 951_868_800),
        (2001, 1, 978_307_200),
        (2100, 60, 4_107_542_400),
    ] {
        assert_eq!(moment(y, d, 0).bucket(unit), seconds);
    }
    for y in [-262_144, -401, -400, -1, 0, 1, 1600, 1900, 1969] {
        assert_eq!(moment(y, 1, 0).bucket(unit), 0);
    }
    assert_eq!(moment(1969, 365, 86_399).bucket(unit), 0);
    assert_eq!(moment(1970, 1, 0).bucket(unit), 0);
}

#[test]
fn calendar_day_iteration_is_an_independent_reference() {
    let unit = NonZeroU64::new(1).unwrap();
    let mut elapsed = 0_u64;
    for year in 1970..=2400 {
        let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
        for ordinal in 1..=if leap { 366 } else { 365 } {
            assert_eq!(moment(year, ordinal, 17).bucket(unit), elapsed + 17);
            elapsed += 86_400;
        }
    }
}

#[test]
fn same_bucket_and_regressing_time_are_noops() {
    let mut s = store();
    s.moment = moment(1970, 1, 19);
    for seconds in [0, 9, 10, 18, 19] {
        let before = s.clone();
        assert!(!s.publish(255, moment(1970, 1, seconds), 8));
        assert_eq!(s, before);
    }
    assert!(s.publish(0, moment(1970, 1, 20), 8));
}

#[test]
fn stale_key_rejects_before_bootstrap_or_bucket_change() {
    let mut s = store();
    s.selected_epoch = 0;
    s.active = members(3);
    let before = s.clone();
    assert!(!s.publish(255, moment(2025, 1, 0), 7));
    assert_eq!(s, before);
}

#[test]
fn bootstrap_requires_zero_selected_and_nonzero_flag_or_exactly_three_members() {
    for selected in [0, 1] {
        for count in 0..=4 {
            for flag in [0, 1, 2, 3, 128, 255] {
                let mut s = store();
                s.selected_epoch = selected;
                s.active = members(count);
                let expect = selected == 0 && (flag != 0 || count == 3);
                assert_eq!(s.publish(flag, moment(1970, 1, 0), 8), expect);
                assert_eq!(s.selected_epoch, if expect { 8 } else { selected });
            }
        }
    }
}

#[test]
fn snapshot_owns_old_moment_and_member_copy_but_store_receives_new_moment() {
    let mut s = store();
    let old = s.moment;
    let original = s.active.clone();
    let new = Moment {
        nanos: 999_999_999,
        ..moment(1970, 1, 11)
    };
    assert!(s.publish(0, new, 8));
    s.active.get_mut(&[0; 32]).unwrap().other.fill(255);
    assert_eq!(s.history[&8].members, original);
    assert_eq!(s.history[&8].moment, old);
    assert_eq!(s.moment, new);
    assert_eq!(s.next_epoch, 9);
    assert_eq!(s.selected_epoch, 5);
}

#[test]
fn bootstrap_uses_old_next_not_requested_key() {
    let mut s = store();
    s.selected_epoch = 0;
    assert!(s.publish(1, s.moment, 50));
    assert_eq!(s.selected_epoch, 8);
    assert_eq!(s.next_epoch, 51);
    assert!(s.history.contains_key(&50));
    assert!(!s.history.contains_key(&8));
    assert_eq!(
        s.selected_member(&[10; 20]),
        Err(LookupError::MissingSelectedSnapshot)
    );
}

#[test]
fn ordinary_caller_height_guard_and_old_next_join() {
    let mut s = store();
    s.selected_epoch = 0;
    let before = s.clone();
    assert!(!s.periodic_publish(0, 1, s.moment));
    assert_eq!(s, before);
    assert!(s.periodic_publish(1, 1, s.moment));
    assert_eq!(s.selected_epoch, 8);
    assert_eq!(s.selected_member(&[10; 20]), Ok(()));
}

#[test]
fn next_key_saturates_and_existing_snapshot_is_replaced() {
    let mut s = store();
    s.next_epoch = u64::MAX;
    assert!(s.publish(0, moment(1970, 1, 10), u64::MAX));
    s.active = members(4);
    assert!(s.publish(0, moment(1970, 1, 20), u64::MAX));
    assert_eq!(s.next_epoch, u64::MAX);
    assert_eq!(s.history.len(), 1);
    assert_eq!(s.history[&u64::MAX].members.len(), 4);
    assert_eq!(s.history[&u64::MAX].moment.seconds, 10);
}

#[test]
fn pruning_stops_at_protected_minimum_even_above_one_thousand() {
    for selected in [0, 1, 4, 999, 1000, 5000] {
        let mut s = store();
        s.selected_epoch = selected;
        s.next_epoch = 2000;
        for key in 0..1003 {
            s.history.insert(
                key,
                Snapshot {
                    members: members(1),
                    moment: s.moment,
                },
            );
        }
        assert!(s.publish(0, moment(1970, 1, 10), 2000));
        let removed = selected.min(4);
        assert_eq!(s.history.len(), 1004 - removed as usize);
        assert_eq!(*s.history.first_key_value().unwrap().0, removed);
    }
}

#[test]
fn selected_membership_never_falls_back_to_newest_or_active() {
    let mut s = store();
    s.history.insert(
        5,
        Snapshot {
            members: members(1),
            moment: s.moment,
        },
    );
    assert!(s.periodic_publish(7, 0, moment(1970, 1, 20)));
    assert_eq!(s.selected_member(&[10; 20]), Ok(()));
    assert_eq!(
        s.selected_member(&[11; 20]),
        Err(LookupError::MissingSigner)
    );
    let mut near = [10; 20];
    near[19] ^= 1;
    assert_eq!(s.selected_member(&near), Err(LookupError::MissingSigner));
    s.selected_epoch = 7;
    assert_eq!(
        s.selected_member(&[10; 20]),
        Err(LookupError::MissingSelectedSnapshot)
    );
    assert_eq!(LookupError::MissingSigner.diagnostic(), 0x2b);
    assert_eq!(LookupError::MissingSelectedSnapshot.diagnostic(), 0x9b);
}

#[test]
fn nanoseconds_and_date_flags_do_not_advance_bucket() {
    let s = store();
    for nanos in [0, 1, 999_999_999, u32::MAX] {
        for flags in 0..16 {
            let m = Moment {
                packed_date: (s.moment.packed_date & !15) | flags,
                nanos,
                ..s.moment
            };
            assert_eq!(m.bucket(s.period), s.moment.bucket(s.period));
        }
    }
}
