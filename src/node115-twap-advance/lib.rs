//! Typed selected TWAP advance transition with a logical tracker and min heap.
//! Native collection layout, finish action and leap-second inputs are excluded.
#![forbid(unsafe_code)]

use node115_daycount_date::node115_date_from_ce_days;
use std::{
    cmp::Reverse,
    collections::{BTreeMap, BinaryHeap},
};

const NANOS: i128 = 1_000_000_000;
const DAY: i128 = 86_400;

/// Valid non-leap-second moment: CE day count, second within day and nanos.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Moment {
    days: i32,
    seconds: u32,
    nanos: u32,
}
impl Moment {
    pub fn new(days: i32, seconds: u32, nanos: u32) -> Option<Self> {
        (node115_date_from_ce_days(days) != 0 && seconds < 86_400 && nanos < 1_000_000_000)
            .then_some(Self {
                days,
                seconds,
                nanos,
            })
    }
    pub fn fields(self) -> (i32, u32, u32) {
        (self.days, self.seconds, self.nanos)
    }
    fn total(self) -> i128 {
        (i128::from(self.days) * DAY + i128::from(self.seconds)) * NANOS + i128::from(self.nanos)
    }
    fn from_total(value: i128) -> Option<Self> {
        let sec = value.div_euclid(NANOS);
        let days = i32::try_from(sec.div_euclid(DAY)).ok()?;
        Self::new(
            days,
            sec.rem_euclid(DAY) as u32,
            value.rem_euclid(NANOS) as u32,
        )
    }
    fn max() -> Self {
        // Last representable proleptic-Gregorian day in the helper's domain.
        let y = 262_142i64 - 1;
        let days = (365 * y + y / 4 - y / 100 + y / 400 + 365) as i32;
        Self::new(days, 86_399, 999_999_999).expect("maximum date")
    }
    fn add(self, nanos: i128) -> Self {
        Self::from_total(self.total() + nanos).unwrap_or_else(Self::max)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Order {
    pub total: u64,
    pub filled: u64,
    pub duration: f64,
    pub counter: u64,
    pub due: Moment,
}

/// Ordering matches the selected heap's date, time, user and order-key tie breaks.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct QueueEntry {
    pub days: i32,
    pub seconds: u32,
    pub nanos: u32,
    pub user: [u8; 20],
    pub order_id: u64,
}

#[derive(Default)]
pub struct Tracker {
    pub users: BTreeMap<[u8; 20], BTreeMap<u64, Order>>,
    pub queue: BinaryHeap<Reverse<QueueEntry>>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    MissingOrder { inserted_user: bool },
    Finish,
    Rescheduled,
}

fn steps(duration: f64) -> u64 {
    let v = duration / 60.0;
    let n = if v.is_finite() { v as u64 } else { 0 };
    n.saturating_mul(2).saturating_add(1)
}

/// Update a selected logical order and, unless finished, insert its due entry.
/// `Finish` is the state at handoff before the separate native finish function;
/// it does not remove the order or model that function's effects. Existing heap
/// entries must describe canonical valid non-leap moments.
pub fn advance(tracker: &mut Tracker, user: [u8; 20], id: u64, now: Moment) -> Outcome {
    let inserted_user = !tracker.users.contains_key(&user);
    let orders = tracker.users.entry(user).or_default();
    let Some(order) = orders.get_mut(&id) else {
        return Outcome::MissingOrder { inserted_user };
    };
    let mut due = order.due.add(30 * NANOS);
    if due.total() < now.total() {
        let gap = now.total() - due.total();
        let whole = (gap / NANOS) as f64;
        let fractional = (gap % NANOS) as f64 / 1_000_000_000.0;
        let delay = (((whole + fractional) / 30.0).ceil() * 30.0) as u64;
        let ns = (u128::from(delay) * 1_000_000_000).min(i64::MAX as u128) as i128;
        due = due.add(ns);
    }
    order.counter = order.counter.saturating_add(1);
    order.due = due;
    if order.filled >= order.total || order.counter > steps(order.duration) {
        return Outcome::Finish;
    }
    tracker.queue.push(Reverse(QueueEntry {
        days: due.days,
        seconds: due.seconds,
        nanos: due.nanos,
        user,
        order_id: id,
    }));
    Outcome::Rescheduled
}
