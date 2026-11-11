//! Logical keyed-state implementation of the node115 builder-approval writer.
#![no_std]
#![forbid(unsafe_code)]
extern crate alloc;
use alloc::collections::BTreeMap;
pub type Address = [u8; 20];
pub type Approvals = BTreeMap<Address, u64>;
/// The approval-map projection of the full native user table.
pub type Users = BTreeMap<Address, Approvals>;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum Status {
    Accepted = 0x1a2,
    TooMany = 0x13c,
}
/// Apply the complete logical approval-map behavior of 0x3c1a510.
///
/// A missing user receives an empty approval map before any branch. Zero removes
/// the builder (or succeeds unchanged) regardless of count. A nonzero write is
/// rejected when the current count is greater than ten, including a replacement
/// of an existing key. At exactly ten a new key may therefore become the eleventh.
/// Raw fee words are preserved; parsing, units and outer policy are not inferred.
pub fn approve(users: &mut Users, user: Address, builder: Address, fee: u64) -> Status {
    let approvals = users.entry(user).or_default();
    if fee == 0 {
        approvals.remove(&builder);
        return Status::Accepted;
    }
    if approvals.len() > 10 {
        return Status::TooMany;
    }
    approvals.insert(builder, fee);
    Status::Accepted
}
