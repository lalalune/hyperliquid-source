//! Owned first-match agent erase and follow-up replacement for node115.
#![no_std]
#![forbid(unsafe_code)]
extern crate alloc;
use alloc::{
    collections::{BTreeMap, BTreeSet},
    string::String,
    vec::Vec,
};
use node115_daycount_date::node115_date_from_ce_days;
pub type Address = [u8; 20];

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Moment {
    day: i32,
    second: u32,
    nanos: u32,
}
impl Moment {
    /// Chrono's valid time projection permits leap nanoseconds only at second59.
    pub fn new(day: i32, second: u32, nanos: u32) -> Option<Self> {
        if node115_date_from_ce_days(day) == 0
            || second >= 86400
            || nanos >= 2_000_000_000
            || (nanos >= 1_000_000_000 && second % 60 != 59)
        {
            return None;
        }
        Some(Self { day, second, nanos })
    }
    pub const fn parts(self) -> (i32, u32, u32) {
        (self.day, self.second, self.nanos)
    }
    pub const MAX: Self = Self {
        day: 95745399,
        second: 86399,
        nanos: 999999999,
    };
    /// Native constant 6.0 -> duration(6s,0ns), then checked calendar addition.
    pub fn after_six_seconds(self) -> Self {
        let total = self.second + 6;
        let nanos = if self.nanos >= 1_000_000_000 {
            self.nanos - 1_000_000_000
        } else {
            self.nanos
        };
        Self::new(self.day + (total / 86400) as i32, total % 86400, nanos).unwrap_or(Self::MAX)
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Agent {
    pub name: String,
    /// Native row+0x18..+0x23 is retained without assigning a meaning.
    pub opaque: [u8; 12],
    pub address: Address,
}
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Followup {
    pub agent: Address,
    pub at: Moment,
}
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct State {
    pub agents: BTreeMap<Address, Vec<Agent>>,
    pub followups: BTreeMap<Address, BTreeSet<Followup>>,
}
/// Creates a missing owner entry even on no match. Erases only the first exact
/// name, preserves remaining order, and REPLACES the owner's follow-up set.
pub fn erase(state: &mut State, owner: Address, name: &str, now: Moment) -> u16 {
    let agents = state.agents.entry(owner).or_default();
    let Some(index) = agents
        .iter()
        .position(|a| a.name.as_bytes() == name.as_bytes())
    else {
        return 0x5c;
    };
    let removed = agents.remove(index);
    let record = Followup {
        agent: removed.address,
        at: now.after_six_seconds(),
    };
    state.followups.insert(owner, BTreeSet::from([record]));
    0x1a2
}
