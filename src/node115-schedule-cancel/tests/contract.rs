use node115_schedule_cancel::*;
use std::collections::BTreeMap;
const A: Address = [1; 20];
const B: Address = [2; 20];
fn ms(x: u64) -> Moment {
    Moment::from_unix_millis(x).unwrap()
}
fn eligible() -> Volumes {
    Volumes {
        perpetual: vec![],
        spot: BTreeMap::from([(
            A,
            Volume {
                scaled: 100_000_000,
                raw: 0,
            },
        )]),
    }
}

#[test]
fn admission_priority_and_clear_are_stateful() {
    let mut t = Tracker::default();
    t.entries.insert(
        A,
        Entry {
            fired_count: 10,
            deadline: Some(ms(20_000)),
        },
    );
    let old = t.clone();
    assert_eq!(
        request(&mut t, &Volumes::default(), A, None, ms(0)),
        Outcome::InsufficientVolume { reported: 0.0 }
    );
    assert_eq!(t, old);
    assert_eq!(
        request(&mut t, &eligible(), A, Some(u64::MAX), ms(0)),
        Outcome::TimestampOutOfRange
    );
    assert_eq!(
        request(&mut t, &eligible(), A, Some(5_000), ms(0)),
        Outcome::DeadlineTooSoon
    );
    assert_eq!(t, old);
    assert_eq!(
        request(&mut t, &eligible(), A, Some(5_001), ms(0)),
        Outcome::TooManyTriggers
    );
    assert_eq!(t, old);
    assert_eq!(
        request(&mut t, &eligible(), A, None, ms(0)),
        Outcome::Accepted
    );
    assert_eq!(
        t.entries[&A],
        Entry {
            fired_count: 10,
            deadline: None
        }
    );
    let mut v = eligible();
    v.spot.insert(
        B,
        Volume {
            scaled: 100_000_000,
            raw: 0,
        },
    );
    assert_eq!(request(&mut t, &v, B, None, ms(0)), Outcome::Accepted);
    assert!(!t.entries.contains_key(&B));
    assert_eq!(request(&mut t, &v, B, Some(5001), ms(0)), Outcome::Accepted);
    assert_eq!(
        t.entries[&B],
        Entry {
            fired_count: 0,
            deadline: Some(ms(5001))
        }
    );
}
#[test]
fn aggregate_maps_saturate_lanes_independently() {
    let v = Volumes {
        perpetual: vec![
            BTreeMap::from([
                (
                    A,
                    Volume {
                        scaled: 60_000_000,
                        raw: u64::MAX,
                    },
                ),
                (
                    B,
                    Volume {
                        scaled: u64::MAX,
                        raw: 0,
                    },
                ),
            ]),
            BTreeMap::new(),
            BTreeMap::from([(
                A,
                Volume {
                    scaled: 40_000_000,
                    raw: 1,
                },
            )]),
        ],
        spot: BTreeMap::from([(
            A,
            Volume {
                scaled: u64::MAX,
                raw: 100,
            },
        )]),
    };
    assert_eq!(
        v.aggregate(A),
        Volume {
            scaled: u64::MAX,
            raw: u64::MAX
        }
    );
    assert_eq!(v.aggregate([3; 20]), Volume::default());
    let mut t = Tracker::default();
    assert_eq!(request(&mut t, &v, A, Some(5001), ms(0)), Outcome::Accepted);
    let low = Volumes {
        perpetual: vec![],
        spot: BTreeMap::from([(
            A,
            Volume {
                scaled: 99_999_999,
                raw: u64::MAX,
            },
        )]),
    };
    assert_eq!(
        request(&mut t, &low, A, None, ms(0)),
        Outcome::InsufficientVolume {
            reported: 999_999.99
        }
    );
}
#[test]
fn due_transition_saturation_and_reset() {
    let mut t = Tracker {
        entries: BTreeMap::from([
            (
                A,
                Entry {
                    fired_count: 9,
                    deadline: Some(ms(10_000)),
                },
            ),
            (
                B,
                Entry {
                    fired_count: u64::MAX,
                    deadline: Some(ms(9_999)),
                },
            ),
            (
                [3; 20],
                Entry {
                    fired_count: 50,
                    deadline: Some(ms(10_001)),
                },
            ),
            (
                [4; 20],
                Entry {
                    fired_count: 2,
                    deadline: None,
                },
            ),
        ]),
    };
    assert_eq!(
        collect_due(&mut t, ms(10_000))
            .into_iter()
            .collect::<Vec<_>>(),
        vec![A, B]
    );
    assert_eq!(
        t.entries[&A],
        Entry {
            fired_count: 10,
            deadline: None
        }
    );
    assert_eq!(
        t.entries[&B],
        Entry {
            fired_count: u64::MAX,
            deadline: None
        }
    );
    assert!(collect_due(&mut t, ms(10_000)).is_empty());
    assert_eq!(
        request(&mut t, &eligible(), A, Some(20_000), ms(10_000)),
        Outcome::TooManyTriggers
    );
    reset_counts(&mut t);
    assert_eq!(
        t.entries,
        BTreeMap::from([(
            [3; 20],
            Entry {
                fired_count: 0,
                deadline: Some(ms(10_001))
            }
        )])
    );
    assert_eq!(
        request(&mut t, &eligible(), A, Some(20_000), ms(10_000)),
        Outcome::Accepted
    );
}
#[test]
fn calendar_nanos_and_fallback() {
    let mut t = Tracker::default();
    let v = eligible();
    let now = Moment::new(719_163, 0, 1).unwrap();
    assert_eq!(
        request(&mut t, &v, A, Some(5000), now),
        Outcome::DeadlineTooSoon
    );
    assert_eq!(request(&mut t, &v, A, Some(5001), now), Outcome::Accepted);
    assert_eq!(
        request(&mut t, &v, A, Some(u64::MAX), Moment::maximum()),
        Outcome::TimestampOutOfRange
    );
    let (days, _, _) = Moment::maximum().fields();
    let last_ms = (days as u64 - 719_163) * 86_400_000 + 86_399_999;
    assert_eq!(
        request(&mut t, &v, A, Some(last_ms), Moment::maximum()),
        Outcome::DeadlineTooSoon
    );
    assert_eq!(
        Moment::from_unix_millis(last_ms).unwrap().fields(),
        (days, 86399, 999_000_000)
    );
    assert!(Moment::from_unix_millis(last_ms + 1).is_none());
    assert!(Moment::new(719_163, 86400, 0).is_none());
    assert!(Moment::new(719_163, 0, 1_000_000_000).is_none());
    // Last millisecond of 1999 plus 5 seconds crosses the year boundary.
    assert_eq!(
        request(&mut t, &v, A, Some(946_684_804_999), ms(946_684_799_999)),
        Outcome::DeadlineTooSoon
    );
    assert_eq!(
        request(&mut t, &v, A, Some(946_684_805_000), ms(946_684_799_999)),
        Outcome::Accepted
    );
}

#[test]
fn independent_timer_state_cases() {
    let mut cases = 0;
    for line in include_str!("reference-vectors.txt")
        .lines()
        .filter(|l| !l.starts_with('#'))
    {
        let (a, b) = line.split_once(" | ").unwrap();
        let x: Vec<i128> = a.split_whitespace().map(|v| v.parse().unwrap()).collect();
        let y: Vec<i128> = b.split_whitespace().map(|v| v.parse().unwrap()).collect();
        let mut v = Volumes::default();
        for k in 0..3 {
            let mut map = BTreeMap::from([(
                B,
                Volume {
                    scaled: u64::MAX,
                    raw: u64::MAX,
                },
            )]);
            if x[12] as u8 & (1 << k) != 0 {
                map.insert(
                    A,
                    Volume {
                        scaled: x[6 + 2 * k] as u64,
                        raw: x[7 + 2 * k] as u64,
                    },
                );
            }
            if k < 2 {
                v.perpetual.push(map);
            } else {
                v.spot = map;
            }
        }
        let mut t = Tracker::default();
        let old = if x[5] < 0 {
            None
        } else {
            Some(ms(x[5] as u64))
        };
        if x[3] != 0 {
            t.entries.insert(
                A,
                Entry {
                    fired_count: x[4] as u64,
                    deadline: old,
                },
            );
        }
        let unrelated = Entry {
            fired_count: 42,
            deadline: Some(Moment::maximum()),
        };
        t.entries.insert(B, unrelated);
        let (day, sec, nanos) = ms(x[0] as u64).fields();
        let now = Moment::new(day, sec, nanos + x[1] as u32).unwrap();
        assert_eq!(
            v.aggregate(A),
            Volume {
                scaled: y[0] as u64,
                raw: y[1] as u64
            },
            "aggregate {cases}"
        );
        let requested = if x[2] < 0 { None } else { Some(x[2] as u64) };
        let result = request(&mut t, &v, A, requested, now);
        assert_eq!(result.native_tag(), y[2] as u16, "status {cases}");
        let reported = match result {
            Outcome::InsufficientVolume { reported } => reported.to_bits(),
            _ => 0,
        };
        assert_eq!(reported, y[3] as u64, "report {cases}");
        let check = |tracker: &Tracker, present: i128, count: i128, deadline: i128| {
            assert_eq!(
                tracker.entries.contains_key(&A),
                present != 0,
                "exists {cases}"
            );
            if present != 0 {
                assert_eq!(
                    tracker.entries[&A],
                    Entry {
                        fired_count: count as u64,
                        deadline: if deadline < 0 {
                            None
                        } else {
                            Some(ms(deadline as u64))
                        }
                    },
                    "entry {cases}"
                );
            }
        };
        check(&t, y[4], y[5], y[6]);
        let due = collect_due(&mut t, ms(x[13] as u64));
        assert_eq!(due.contains(&A), y[7] != 0, "due {cases}");
        assert!(!due.contains(&B));
        if x[14] != 0 {
            reset_counts(&mut t);
        }
        check(&t, y[8], y[9], y[10]);
        assert_eq!(
            t.entries[&B],
            Entry {
                fired_count: if x[14] != 0 { 0 } else { 42 },
                ..unrelated
            }
        );
        cases += 1;
    }
    assert_eq!(cases, 14000);
}
