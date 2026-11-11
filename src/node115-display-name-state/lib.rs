//! Logical keyed-state implementation of the selected display-name core.
#![no_std]
#![forbid(unsafe_code)]
extern crate alloc;
use alloc::{collections::BTreeMap, string::String};
pub type Address = [u8; 20];
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum Status {
    Accepted = 0x1a2,
    TooLong = 0xe2,
    TooShort = 0xe3,
    Duplicate = 0xe4,
}

/// Apply the core to valid logical state, comparing UTF-8 string bytes exactly.
/// The caller's own existing value participates in the duplicate scan.
pub fn set_name(names: &mut BTreeMap<Address, String>, user: Address, name: String) -> Status {
    let len = name.len();
    if len == 0 {
        names.remove(&user);
        return Status::Accepted;
    }
    if len > 20 {
        return Status::TooLong;
    }
    if len < 3 {
        return Status::TooShort;
    }
    if names.values().any(|old| old.as_bytes() == name.as_bytes()) {
        return Status::Duplicate;
    }
    names.insert(user, name);
    Status::Accepted
}
