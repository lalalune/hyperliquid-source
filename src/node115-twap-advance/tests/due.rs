use node115_twap_advance::{Moment, Order, QueueEntry, Tracker};
use std::cmp::Reverse;

fn enqueue(t: &mut Tracker, day: i32, second: u32, nano: u32, user: u8, id: u64) {
    t.queue.push(Reverse(QueueEntry {
        days: day,
        seconds: second,
        nanos: nano,
        user: [user; 20],
        order_id: id,
    }));
}

#[test]
fn heap_time_selects_live_keys_and_stops_at_the_first_live_future_key() {
    let mut t = Tracker::default();
    let now = Moment::new(0, 0, 10).unwrap();
    let live = Order {
        total: 20,
        filled: 0,
        duration: 60.,
        counter: 0,
        due: Moment::new(1, 0, 0).unwrap(),
    };
    t.users.entry([4; 20]).or_default().insert(8, live);
    t.users.entry([5; 20]).or_default().insert(9, live);

    enqueue(&mut t, 0, 1, 0, 5, 9); // first live future key
    enqueue(&mut t, 1, 0, 0, 1, 17); // stale, behind the live key
    enqueue(&mut t, 0, 0, 11, 4, 19); // stale ID belonging to a live user
    enqueue(&mut t, 0, 0, 10, 4, 8); // exactly due
    enqueue(&mut t, 0, 0, 10, 4, 8); // separate queued key
    enqueue(&mut t, -1, 86_399, 999_999_999, 5, 9);
    enqueue(&mut t, -1, 1, 0, 8, 19); // stale user

    assert_eq!(t.take_due(now), [([5; 20], 9), ([4; 20], 8), ([4; 20], 8)]);
    assert_eq!(t.queue.len(), 2);
    assert!(
        t.take_due(Moment::new(0, 0, 999_999_999).unwrap())
            .is_empty()
    );
    assert_eq!(t.take_due(Moment::new(0, 1, 0).unwrap()), [([5; 20], 9)]);
    assert!(t.queue.is_empty());
    assert_eq!(t.users[&[4; 20]][&8].counter, 0);
}
