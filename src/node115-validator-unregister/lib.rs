//! Owned state for the unregister subtype of node115's validator action.
#![no_std]
#![forbid(unsafe_code)]
extern crate alloc;
use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
pub type Address = [u8; 20];

/// Logical projection of the selected record's +0x20 raw word.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockingRecord {
    pub words: [u64; 5],
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Validator {
    /// The exact twenty bytes copied from native value +0x3c.
    pub related_key: Address,
    /// Unobserved owned data, removed with the whole validator entry.
    pub payload: Vec<u8>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoryRow {
    pub key: u64,
    pub payload: Vec<u8>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Followup {
    pub history_key: u64,
    pub action_key: Address,
}
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct State {
    /// State +0x110; only the selected record's final word gates removal.
    pub blocking_records: BTreeMap<Address, BlockingRecord>,
    /// State +0xd0.
    pub validators: BTreeMap<Address, Validator>,
    /// State +0x10, with the observed sixteen-byte value projection.
    pub auxiliary: BTreeMap<Address, [u64; 2]>,
    /// State +0x288, with the observed twenty-four-byte value projection.
    pub timestamps: BTreeMap<Address, [u64; 3]>,
    /// State +0x48, in native logical iteration order. No sorting is performed.
    pub history: Vec<HistoryRow>,
    /// State +0x180.
    pub related_keys: BTreeSet<Address>,
    /// State +0x1e8.
    pub followups: BTreeMap<Address, Followup>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum Status {
    Accepted = 0x1a2,
    Blocked = 0x144,
    MissingValidator = 0x95,
}

/// Apply the selected nonzero/non-one subtype after native action decoding.
/// Allocation and normally returning diagnostics are premises; physical map
/// layout, registration/update subtypes and outer authorization are excluded.
pub fn unregister(state: &mut State, action_key: Address) -> Status {
    if state
        .blocking_records
        .get(&action_key)
        .is_some_and(|r| r.words[4] != 0)
    {
        return Status::Blocked;
    }
    let Some(validator) = state.validators.get(&action_key) else {
        return Status::MissingValidator;
    };
    let related_key = validator.related_key;
    state.auxiliary.remove(&action_key);
    state.validators.remove(&action_key);
    state.timestamps.remove(&action_key);
    let history_key = state.history.last().map_or(0, |row| row.key);
    state.related_keys.insert(related_key);
    state.followups.insert(
        related_key,
        Followup {
            history_key,
            action_key,
        },
    );
    Status::Accepted
}
