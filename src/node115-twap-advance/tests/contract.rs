use node115_twap_advance::{Moment, Order, Outcome, Tracker, advance};

fn m(day: i32, sec: u32, nano: u32) -> Moment {
    Moment::new(day, sec, nano).unwrap()
}
fn order(due: Moment) -> Order {
    Order {
        total: 100,
        filled: 0,
        duration: 120.0,
        counter: 0,
        due,
    }
}

#[test]
fn missing_user_is_inserted_and_missing_order_is_unchanged() {
    let mut tracker = Tracker::default();
    assert_eq!(
        advance(&mut tracker, [1; 20], 5, m(738886, 0, 0)),
        Outcome::MissingOrder {
            inserted_user: true
        }
    );
    assert!(tracker.users.contains_key(&[1; 20]));
    assert_eq!(
        advance(&mut tracker, [1; 20], 5, m(738886, 0, 0)),
        Outcome::MissingOrder {
            inserted_user: false
        }
    );
    assert!(tracker.queue.is_empty());
}

#[test]
fn next_step_catches_up_and_updates_before_finish() {
    let mut t = Tracker::default();
    let user = [7; 20];
    t.users
        .entry(user)
        .or_default()
        .insert(3, order(m(738886, 0, 500_000_000)));
    assert_eq!(
        advance(&mut t, user, 3, m(738886, 61, 0)),
        Outcome::Rescheduled
    );
    let o = t.users[&user][&3];
    assert_eq!(o.counter, 1);
    assert_eq!(o.due.fields(), (738886, 90, 500_000_000));
    let queued = t.queue.peek().unwrap().0;
    assert_eq!(
        (queued.days, queued.seconds, queued.nanos),
        (738886, 90, 500_000_000)
    );
    t.users.get_mut(&user).unwrap().get_mut(&3).unwrap().filled = 100;
    assert_eq!(advance(&mut t, user, 3, m(738886, 0, 0)), Outcome::Finish);
    assert_eq!(t.users[&user][&3].counter, 2);
}

#[test]
fn heap_orders_due_then_user_then_order() {
    let mut t = Tracker::default();
    for (user, id, seconds) in [
        ([2; 20], 3, 1),
        ([1; 20], 8, 1),
        ([1; 20], 4, 1),
        ([0; 20], 9, 10),
    ] {
        t.users
            .entry(user)
            .or_default()
            .insert(id, order(m(738886, seconds, 0)));
        assert_eq!(
            advance(&mut t, user, id, m(738886, 0, 0)),
            Outcome::Rescheduled
        );
    }
    assert_eq!(t.queue.pop().unwrap().0.order_id, 4);
    assert_eq!(t.queue.pop().unwrap().0.order_id, 8);
    assert_eq!(t.queue.pop().unwrap().0.order_id, 3);
    assert_eq!(t.queue.pop().unwrap().0.order_id, 9);
}

#[test]
fn duration_counter_and_invalid_moments() {
    assert!(Moment::new(i32::MAX, 0, 0).is_none());
    assert!(Moment::new(738886, 86400, 0).is_none());
    assert!(Moment::new(738886, 0, 1_000_000_000).is_none());
    let mut t = Tracker::default();
    let user = [0; 20];
    let mut o = order(m(738886, 0, 0));
    o.duration = f64::NAN;
    o.counter = 1;
    t.users.entry(user).or_default().insert(1, o);
    assert_eq!(advance(&mut t, user, 1, m(738886, 0, 0)), Outcome::Finish);
    assert_eq!(t.users[&user][&1].counter, 2);
}

#[test]
fn maximum_date_uses_saturated_fallback() {
    let y = 262_142i64 - 1;
    let max_day = (365 * y + y / 4 - y / 100 + y / 400 + 365) as i32;
    let mut t = Tracker::default();
    let user = [3; 20];
    t.users
        .entry(user)
        .or_default()
        .insert(7, order(m(max_day, 86_399, 999_999_999)));
    assert_eq!(
        advance(&mut t, user, 7, m(max_day, 0, 0)),
        Outcome::Rescheduled
    );
    assert_eq!(
        t.users[&user][&7].due.fields(),
        (max_day, 86_399, 999_999_999)
    );
}

#[test]
fn one_pass_cap_and_max_counter_are_preserved() {
    let mut t = Tracker::default();
    let user = [4; 20];
    let mut o = order(m(1, 0, 0));
    o.counter = u64::MAX;
    o.duration = 1e300;
    t.users.entry(user).or_default().insert(7, o);
    assert_eq!(
        advance(&mut t, user, 7, m(400000, 0, 0)),
        Outcome::Rescheduled
    );
    let updated = t.users[&user][&7];
    assert_eq!(updated.counter, u64::MAX);
    assert_eq!(updated.due.fields().2, 854_775_807);
    assert!(updated.due.fields().0 < 400000);
}

#[test]
fn independent_calendar_and_float_cases() {
    let mut count = 0;
    for line in include_str!("reference-vectors.txt")
        .lines()
        .filter(|s| !s.starts_with('#'))
    {
        let v: Vec<_> = line.split_whitespace().collect();
        let due = m(
            v[0].parse().unwrap(),
            v[1].parse().unwrap(),
            v[2].parse().unwrap(),
        );
        let now = m(
            v[3].parse().unwrap(),
            v[4].parse().unwrap(),
            v[5].parse().unwrap(),
        );
        let o = Order {
            total: v[6].parse().unwrap(),
            filled: v[7].parse().unwrap(),
            counter: v[8].parse().unwrap(),
            duration: f64::from_bits(u64::from_str_radix(v[9], 16).unwrap()),
            due,
        };
        let mut t = Tracker::default();
        let user = [9; 20];
        t.users.entry(user).or_default().insert(0, o);
        let got = advance(&mut t, user, 0, now);
        let finish = v[14] == "1";
        assert_eq!(
            got,
            if finish {
                Outcome::Finish
            } else {
                Outcome::Rescheduled
            },
            "case {count}"
        );
        let updated = t.users[&user][&0];
        assert_eq!(
            updated.due.fields(),
            (
                v[10].parse().unwrap(),
                v[11].parse().unwrap(),
                v[12].parse().unwrap()
            ),
            "case {count}"
        );
        assert_eq!(updated.counter, v[13].parse().unwrap(), "case {count}");
        assert_eq!(t.queue.len(), usize::from(!finish));
        count += 1;
    }
    assert_eq!(count, 6000);
}
