//! Owned logical reconstruction of node115 ordinary validator snapshot publication.
//! This is not a signature verifier, complete action gate, or native container ABI.
#![no_std]
extern crate alloc;

use alloc::collections::BTreeMap;
use core::num::NonZeroU64;

/// Caller-valid packed calendar date, seconds within a day, and opaque nanoseconds.
/// The low four date bits and nanoseconds do not participate in bucket selection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Moment {
    pub packed_date: i32,
    pub seconds: u32,
    pub nanos: u32,
}

impl Moment {
    /// Requires a valid packed Gregorian year/ordinal and seconds within the day.
    /// No wall clock, timezone lookup, target code, or epoch-state input is used.
    pub fn bucket(self, period: NonZeroU64) -> u64 {
        let y = i64::from(self.packed_date >> 13) - 1;
        let ordinal = i64::from((self.packed_date >> 4) & 0x1ff);
        let days =
            365 * y + y.div_euclid(4) - y.div_euclid(100) + y.div_euclid(400) + ordinal - 719_163;
        let seconds = days * 86_400 + i64::from(self.seconds);
        seconds.max(0) as u64 / period.get()
    }
}

/// The 20-byte address used by the selected-snapshot lookup plus owned other data.
/// The native row has a distinct 32-byte map key; that key is not the signer address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member<T> {
    pub signer: [u8; 20],
    pub other: T,
}
pub type Members<T> = BTreeMap<[u8; 32], Member<T>>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot<T> {
    pub members: Members<T>,
    /// Native publication copies the previous store moment into the snapshot.
    pub moment: Moment,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Store<T> {
    pub history: BTreeMap<u64, Snapshot<T>>,
    pub active: Members<T>,
    pub moment: Moment,
    pub period: NonZeroU64,
    pub selected_epoch: u64,
    pub next_epoch: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LookupError {
    MissingSelectedSnapshot,
    MissingSigner,
}
impl LookupError {
    /// Diagnostic codes used by 0x36c8430, not the enclosing gate's result code.
    pub const fn diagnostic(self) -> u16 {
        match self {
            Self::MissingSelectedSnapshot => 0x9b,
            Self::MissingSigner => 0x2b,
        }
    }
}

impl<T: Clone> Store<T> {
    /// Logical normal-return behavior of 0x36cab90 on valid owned maps.
    /// Physical map conversions, allocations, logging and unwind behavior are excluded.
    pub fn publish(&mut self, raw_flag: u8, new_moment: Moment, requested_epoch: u64) -> bool {
        if requested_epoch < self.next_epoch {
            return false;
        }
        let bootstrap = self.selected_epoch == 0 && (raw_flag != 0 || self.active.len() == 3);
        if new_moment.bucket(self.period) <= self.moment.bucket(self.period) && !bootstrap {
            return false;
        }
        self.history.insert(
            requested_epoch,
            Snapshot {
                members: self.active.clone(),
                moment: self.moment,
            },
        );
        if bootstrap {
            self.selected_epoch = self.next_epoch;
        }
        self.next_epoch = requested_epoch.saturating_add(1);
        self.moment = new_moment;
        while self.history.len() > 1_000 {
            match self.history.first_key_value() {
                Some((&key, _)) if key < self.selected_epoch => {
                    self.history.pop_first();
                }
                _ => break,
            }
        }
        true
    }

    /// Caller projection: height zero skips publication; otherwise use the old next key.
    /// Later caller side effects are not reconstructed here.
    pub fn periodic_publish(&mut self, height: u64, raw_flag: u8, moment: Moment) -> bool {
        height != 0 && self.publish(raw_flag, moment, self.next_epoch)
    }

    /// The membership subcheck consumed by signed-action admission. No crypto claim.
    pub fn selected_member(&self, signer: &[u8; 20]) -> Result<(), LookupError> {
        let snapshot = self
            .history
            .get(&self.selected_epoch)
            .ok_or(LookupError::MissingSelectedSnapshot)?;
        if snapshot
            .members
            .values()
            .any(|member| &member.signer == signer)
        {
            Ok(())
        } else {
            Err(LookupError::MissingSigner)
        }
    }
}
