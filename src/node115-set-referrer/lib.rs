//! Owned keyed-state implementation of the selected node115 set-referrer core.
#![no_std]
#![forbid(unsafe_code)]
extern crate alloc;
use alloc::{collections::BTreeMap, string::String};
use node115_daycount_date::node115_date_from_ce_days;
pub type Address = [u8; 20];
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Moment {
    days: i32,
    seconds: u32,
    nanos: u32,
}
impl Moment {
    /// Canonical non-leap-second native calendar domain, expressed as CE days.
    pub fn new(days: i32, seconds: u32, nanos: u32) -> Option<Self> {
        (node115_date_from_ce_days(days) != 0 && seconds < 86400 && nanos < 1_000_000_000)
            .then_some(Self {
                days,
                seconds,
                nanos,
            })
    }
    pub fn parts(self) -> (i32, u32, u32) {
        (self.days, self.seconds, self.nanos)
    }
    fn positive_unix_millis(self) -> u64 {
        let ms = (i64::from(self.days) - 719_163) * 86_400_000
            + i64::from(self.seconds) * 1000
            + i64::from(self.nanos / 1_000_000);
        ms.max(0) as u64
    }
}
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct User {
    pub referrer: Option<Address>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Referrer {
    pub history: BTreeMap<Address, Moment>,
    pub remaining: u64,
    pub bucket: u64,
    pub configured_quota: u64,
}
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct State {
    pub codes: BTreeMap<String, Address>,
    pub users: BTreeMap<Address, User>,
    pub referrers: BTreeMap<Address, Referrer>,
    pub period_millis: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum Status {
    MissingCode = 0xa6,
    SelfReferral = 0xa2,
    AlreadySet = 0xa3,
    QuotaExceeded = 0xa5,
    Accepted = 0x1a2,
}
/// Apply 0x3c17590's complete logical-map state contract on valid owned input.
///
/// Code matching is exact and case-sensitive. A resolved non-self code creates
/// the user before later gates. A code whose referrer record is absent returns
/// Accepted without assigning the user. No outer decoder/eligibility is inferred.
pub fn set_referrer(state: &mut State, user: Address, code: &str, now: Moment) -> Status {
    let Some(&referrer) = state.codes.get(code) else {
        return Status::MissingCode;
    };
    if referrer == user {
        return Status::SelfReferral;
    }
    let user_row = state.users.entry(user).or_default();
    if user_row.referrer.is_some() {
        return Status::AlreadySet;
    }
    let Some(record) = state.referrers.get_mut(&referrer) else {
        return Status::Accepted;
    };
    if state.period_millis == 0 {
        return Status::QuotaExceeded;
    }
    let bucket = now.positive_unix_millis() / state.period_millis;
    if bucket != record.bucket {
        record.bucket = bucket;
        record.remaining = record.configured_quota.max(1000);
    } else if record.remaining == 0 {
        return Status::QuotaExceeded;
    }
    record.remaining -= 1;
    record.history.insert(user, now);
    user_row.referrer = Some(referrer);
    Status::Accepted
}
