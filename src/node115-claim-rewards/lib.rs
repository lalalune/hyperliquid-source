//! Selected normal-path reward row writer; see the accompanying research packet.
#![no_std]
#![forbid(unsafe_code)]
extern crate alloc;

use alloc::{collections::BTreeMap, vec::Vec};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Metadata {
    pub decimals: u8,
    pub width: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Row {
    pub key: u64,
    pub pending: u64,
    pub claimed: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Fault {
    MissingMetadata,
    InvalidExponent,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Outcome {
    pub status: u16,
    pub claims: Vec<(u64, u64)>,
}

fn power10(a: u8, b: u8) -> Result<u64, Fault> {
    let exp = a.checked_sub(b).ok_or(Fault::InvalidExponent)?;
    10u64
        .checked_pow(u32::from(exp))
        .ok_or(Fault::InvalidExponent)
}

/// Look up a user and process its rows in the supplied native iterator order.
/// Invalid metadata is a local fault standing in for excluded native panic paths.
/// Earlier row mutations remain visible if a later row faults.
pub fn claim(
    users: &mut BTreeMap<[u8; 20], Vec<Row>>,
    user: &[u8; 20],
    metadata: &[Metadata],
) -> Result<Outcome, Fault> {
    let mut out = Outcome {
        status: 0xaa,
        claims: Vec::new(),
    };
    let Some(rows) = users.get_mut(user) else {
        return Ok(out);
    };
    for row in rows {
        let amount = row.pending;
        if amount == 0 {
            continue;
        }
        let first = metadata.first().ok_or(Fault::MissingMetadata)?;
        let selected = usize::try_from(row.key)
            .ok()
            .and_then(|i| metadata.get(i))
            .ok_or(Fault::MissingMetadata)?;
        let denominator = power10(first.width, selected.decimals)?;
        let scale = power10(selected.width, selected.decimals)?;
        let floor = (100_000_000u128 * u128::from(scale)) / u128::from(denominator);
        if floor > u128::from(u64::MAX) || u128::from(amount) < floor {
            out.status = 0xab;
            continue;
        }
        row.pending = 0;
        row.claimed = row.claimed.saturating_add(amount);
        out.claims.push((row.key, amount));
    }
    if !out.claims.is_empty() {
        out.status = 0x1a2;
    }
    Ok(out)
}
