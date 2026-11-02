//! Conditional node94 supplied-summary residual values, independently reconstructed.
//!
//! The caller supplies the post-worker state and summaries. This crate does not
//! run the worker, compute rates, construct missing positions, or reproduce the
//! native ABI. See the evidence packet and README for the correspondence domain.
#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

/// An opaque address, ordered by its unsigned bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Address(pub [u8; 20]);

/// All 72 bytes are preserved. Only the LE u32 at 60..64 controls flattening.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Record(pub [u8; 72]);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Selection {
    pub asset: u64,
    pub magnitude: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Summary {
    pub address: Address,
    pub total: i64,
    pub selection: Option<Selection>,
    pub records: Vec<Record>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Position {
    pub raw_mode: u32,
    pub leverage: u32,
    pub margin: i64,
    pub size: i64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct User {
    pub cross_balance: i64,
    pub position_count: u64,
    pub positions: BTreeMap<u64, Position>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct State {
    pub users: BTreeMap<Address, User>,
    pub aru: BTreeSet<Address>,
    pub auxiliary: BTreeMap<u64, i64>,
    pub users_with_positions: BTreeSet<Address>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Winner {
    pub address: Address,
    pub asset: u64,
    pub magnitude: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Applied {
    pub total: i64,
    pub winner: Option<Winner>,
    pub records: Vec<Record>,
}

/// A safe-source refusal, not a captured ABI discriminant or native rollback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    DuplicateSummary,
    Span,
    MissingUser,
    MissingPosition,
    SizeMagnitude,
}

/// Admit native-derived 104/80-byte summary and 72-byte input-record counts.
///
/// Counts are mathematical: this does not allocate or promise a Rust capacity.
/// Bounding all input records (including discarded suffixes) is a conservative
/// safe policy. The actual operation calls this after checked length addition.
pub fn checked_counts(summaries: u64, input_records: u64) -> Result<(), Error> {
    let limit = i64::MAX as u64;
    if summaries > limit / 104 || summaries > limit / 80 || input_records > limit / 72 {
        return Err(Error::Span);
    }
    Ok(())
}

/// Consume unique summaries and apply one residual to an existing position.
///
/// Typed errors leave `state` unchanged. Ordinary allocation success is required;
/// no allocation failure, panic or arbitrary drop atomicity is claimed. Unused
/// selected state is not validated when total is zero or no winner exists.
pub fn apply_supplied_summaries(
    mut summaries: Vec<Summary>,
    state: &mut State,
) -> Result<Applied, Error> {
    let count = u64::try_from(summaries.len()).map_err(|_| Error::Span)?;
    let input_records = summaries.iter().try_fold(0_u64, |n, summary| {
        let len = u64::try_from(summary.records.len()).map_err(|_| Error::Span)?;
        n.checked_add(len).ok_or(Error::Span)
    })?;
    checked_counts(count, input_records)?;
    summaries.sort_unstable_by_key(|summary| summary.address);
    if summaries
        .windows(2)
        .any(|pair| pair[0].address == pair[1].address)
    {
        return Err(Error::DuplicateSummary);
    }

    let mut total = 0_i64;
    let mut winner: Option<Winner> = None;
    let mut records = Vec::new();
    for summary in summaries {
        total = total.saturating_add(summary.total);
        if let Some(selection) = summary.selection {
            if winner.is_none_or(|old| selection.magnitude > old.magnitude) {
                winner = Some(Winner {
                    address: summary.address,
                    asset: selection.asset,
                    magnitude: selection.magnitude,
                });
            }
        }
        for record in summary.records {
            let sentinel = u32::from_le_bytes(record.0[60..64].try_into().expect("fixed record"));
            if sentinel == 0 {
                break;
            }
            records.push(record);
        }
    }

    if total != 0 {
        if let Some(selected) = winner {
            // Admit every typed failure before the first state write.
            let user = state
                .users
                .get(&selected.address)
                .ok_or(Error::MissingUser)?;
            let position = user
                .positions
                .get(&selected.asset)
                .ok_or(Error::MissingPosition)?;
            let magnitude = position.size.checked_abs().ok_or(Error::SizeMagnitude)?;
            state.aru.insert(selected.address);
            let user = state
                .users
                .get_mut(&selected.address)
                .expect("pre-admitted user");
            let position = user
                .positions
                .get_mut(&selected.asset)
                .expect("pre-admitted position");
            if position.raw_mode == 1 {
                position.margin = position.margin.saturating_sub(total);
            } else {
                user.cross_balance = user.cross_balance.saturating_sub(total);
            }
            let auxiliary = state.auxiliary.entry(selected.asset).or_insert(0);
            *auxiliary = auxiliary.saturating_sub(magnitude);
            *auxiliary = auxiliary.saturating_add(magnitude);
        }
    }
    Ok(Applied {
        total,
        winner,
        records,
    })
}
