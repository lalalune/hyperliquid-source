//! Selected normal-return governance vote state operation.
#![no_std]
#![forbid(unsafe_code)]
extern crate alloc;
use alloc::{collections::BTreeMap, vec::Vec};
pub type Address = [u8; 20];
pub type ProposalKey = [u8; 32];
/// First component compares signed; the following components compare unsigned.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Cursor {
    pub first: i32,
    pub second: u32,
    pub third: u32,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AmountRow {
    pub amount: u64,
    pub cursor: Cursor,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Vote {
    pub amount: u64,
    pub choice: u8,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Proposal {
    pub cursor: Cursor,
    pub votes: BTreeMap<Address, Vote>,
}
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct State {
    pub proposals: BTreeMap<ProposalKey, Proposal>,
    pub amount_rows: BTreeMap<Address, Vec<AmountRow>>,
    pub markers: BTreeMap<Address, Cursor>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum Status {
    MissingProposal = 0x114,
    Duplicate = 0x115,
    ZeroAmount = 0x116,
    TooLate = 0x117,
    Accepted = 0x1a2,
}

/// Apply the selected core over valid logical keyed state in native row order.
/// Outer authorization, allocation, native ABI and exceptional paths are excluded.
pub fn vote(
    state: &mut State,
    proposal: ProposalKey,
    voter: Address,
    choice: u8,
    now: Cursor,
) -> Status {
    let Some(p) = state.proposals.get(&proposal) else {
        return Status::MissingProposal;
    };
    if now > p.cursor {
        return Status::TooLate;
    }
    if p.votes.contains_key(&voter) {
        return Status::Duplicate;
    }
    let Some(rows) = state.amount_rows.get_mut(&voter) else {
        return Status::ZeroAmount;
    };
    let Some(amount) = rows
        .iter()
        .try_fold(0u64, |sum, row| sum.checked_add(row.amount))
    else {
        return Status::ZeroAmount;
    };
    if amount == 0 {
        return Status::ZeroAmount;
    }
    for row in rows {
        row.cursor = row.cursor.max(p.cursor);
    }
    let mut amount = amount;
    if let Some(marker) = state.markers.get_mut(&voter)
        && marker.first != 0
    {
        if now < *marker {
            if amount < (1u64 << 62) {
                amount <<= 2;
            }
        } else {
            marker.first = 0;
        }
    }
    state
        .proposals
        .get_mut(&proposal)
        .unwrap()
        .votes
        .insert(voter, Vote { amount, choice });
    Status::Accepted
}
