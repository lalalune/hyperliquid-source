//! Schedule-cancel dead-man's-switch integration joining `node115-schedule-cancel`
//! with `Book::cancel_all_for_user`.

use node115_assets::qtys::OverflowSink;
use node115_fees::UserAddress;
use node115_schedule_cancel as sc;

use crate::matching::Book;
use crate::slab::OrderRecord;

/// Dead-man's-switch scheduler backed by `node115-schedule-cancel` (`RE-010-schedule-cancel-core-115`).
#[derive(Clone, Debug, Default)]
pub struct ScheduleCancelEngine {
    pub tracker: sc::Tracker,
}

impl ScheduleCancelEngine {
    pub fn new() -> Self {
        Self::default()
    }

    /// Submit a schedule-cancel request for `user` using `#115` `node115-schedule-cancel::request`.
    pub fn request(
        &mut self,
        user: UserAddress,
        now: sc::Moment,
        deadline_ms: Option<u64>,
        volumes: &sc::Volumes,
    ) -> sc::Outcome {
        sc::request(&mut self.tracker, volumes, user, deadline_ms, now)
    }

    /// Collect all users whose scheduled cancel deadline is due at `now` and cancel
    /// every resting order belonging to them across `books`.
    pub fn fire_due(
        &mut self,
        now: sc::Moment,
        books: &mut [&mut Book],
        sink: &mut impl OverflowSink,
    ) -> Vec<(UserAddress, Vec<OrderRecord>)> {
        let due_users = sc::collect_due(&mut self.tracker, now);
        let mut cancelled = Vec::new();
        for user in due_users {
            let mut user_orders = Vec::new();
            for book in books.iter_mut() {
                user_orders.extend(book.cancel_all_for_user(&user, sink));
            }
            cancelled.push((user, user_orders));
        }
        cancelled
    }

    pub fn reset_daily_counts(&mut self) {
        sc::reset_counts(&mut self.tracker);
    }
}
