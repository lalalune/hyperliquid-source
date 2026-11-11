//! Node115 schedule-cancel admission and timer bookkeeping on owned logical maps.
//! Due keys are a handoff projection, not completed order cancellation.
#![forbid(unsafe_code)]
use node115_daycount_date::node115_date_from_ce_days;
use std::collections::{BTreeMap, BTreeSet};
pub type Address = [u8; 20];
const DAY_MS: u64 = 86_400_000;
const NANOS: i128 = 1_000_000_000;

/// Canonical valid Gregorian moment excluding leap-second encodings.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
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
    pub fn from_unix_millis(ms: u64) -> Option<Self> {
        let days = i32::try_from(ms / DAY_MS + 719_163).ok()?;
        Self::new(
            days,
            ((ms / 1000) % 86400) as u32,
            ((ms % 1000) * 1_000_000) as u32,
        )
    }
    fn five_seconds_later(self) -> Self {
        let ns = (i128::from(self.seconds) + 5) * NANOS + i128::from(self.nanos);
        let days = self.days + (ns / (86_400 * NANOS)) as i32;
        Self::new(days, ((ns / NANOS) % 86_400) as u32, (ns % NANOS) as u32)
            .unwrap_or_else(Self::maximum)
    }
    pub fn maximum() -> Self {
        let y = 262_142i64 - 1;
        let day = 365 * y + y / 4 - y / 100 + y / 400 + 365;
        Self::new(day as i32, 86_399, 999_999_999).expect("native maximum date")
    }
}

/// Both aggregate lanes execute even though admission compares only `scaled`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Volume {
    pub scaled: u64,
    pub raw: u64,
}
#[derive(Clone, Debug, Default)]
pub struct Volumes {
    /// Logical user records from each selected perp DEX, in native vector order.
    pub perpetual: Vec<BTreeMap<Address, Volume>>,
    pub spot: BTreeMap<Address, Volume>,
}
impl Volumes {
    pub fn aggregate(&self, user: Address) -> Volume {
        let mut out = Volume::default();
        for map in self.perpetual.iter().chain(std::iter::once(&self.spot)) {
            let value = map.get(&user).copied().unwrap_or_default();
            out.scaled = out.scaled.saturating_add(value.scaled);
            out.raw = out.raw.saturating_add(value.raw);
        }
        out
    }
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Entry {
    pub fired_count: u64,
    pub deadline: Option<Moment>,
}
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Tracker {
    pub entries: BTreeMap<Address, Entry>,
}
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Outcome {
    Accepted,
    InsufficientVolume {
        reported: f64,
    },
    DeadlineTooSoon,
    TooManyTriggers,
    /// Owned error category for the native timestamp-conversion failure.
    TimestampOutOfRange,
}
impl Outcome {
    pub fn native_tag(self) -> u16 {
        match self {
            Self::Accepted => 0x1a2,
            Self::InsufficientVolume { .. } => 0x11d,
            Self::DeadlineTooSoon => 0x11b,
            Self::TooManyTriggers => 0x11c,
            Self::TimestampOutOfRange => 0x89,
        }
    }
}

/// Run the selected complete request core on logical user maps.
/// Missing records contribute zero volume. Every request, including clearing a
/// schedule, passes the aggregate-volume gate first. No trigger counter is
/// consumed by setting/replacing/clearing a deadline.
pub fn request(
    tracker: &mut Tracker,
    volumes: &Volumes,
    user: Address,
    deadline_ms: Option<u64>,
    now: Moment,
) -> Outcome {
    let aggregate = volumes.aggregate(user);
    if aggregate.scaled < 100_000_000 {
        return Outcome::InsufficientVolume {
            reported: aggregate.scaled as f64 / 100.0,
        };
    }
    let Some(ms) = deadline_ms else {
        if let Some(entry) = tracker.entries.get_mut(&user) {
            entry.deadline = None;
        }
        return Outcome::Accepted;
    };
    let Some(deadline) = Moment::from_unix_millis(ms) else {
        return Outcome::TimestampOutOfRange;
    };
    if deadline <= now.five_seconds_later() {
        return Outcome::DeadlineTooSoon;
    }
    let entry = tracker.entries.entry(user).or_default();
    if entry.fired_count > 9 {
        return Outcome::TooManyTriggers;
    }
    entry.deadline = Some(deadline);
    Outcome::Accepted
}

/// Collect due users, saturating their counters and clearing only the deadline.
/// The set projects the keys handed to the separate native cancellation call.
/// It does not execute that call, claim its success or preserve invocation order.
pub fn collect_due(tracker: &mut Tracker, now: Moment) -> BTreeSet<Address> {
    let mut due = BTreeSet::new();
    for (user, entry) in &mut tracker.entries {
        if entry.deadline.is_some_and(|deadline| deadline <= now) {
            due.insert(*user);
            entry.fired_count = entry.fired_count.saturating_add(1);
            entry.deadline = None;
        }
    }
    due
}

/// Reset counters and remove entries without a deadline, preserving active ones.
/// This implements the selected reset helper. The driver invokes it on date
/// advance after cancellation handoffs; that driver and its other work are not
/// implemented here, so the caller chooses when to apply this operation.
pub fn reset_counts(tracker: &mut Tracker) {
    tracker.entries.retain(|_, entry| {
        entry.fired_count = 0;
        entry.deadline.is_some()
    });
}
