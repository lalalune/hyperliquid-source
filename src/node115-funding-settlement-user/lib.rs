//! Owned logical-map projection of node115's per-user funding settlement.
#![no_std]
#![forbid(unsafe_code)]
extern crate alloc;
use alloc::{collections::BTreeMap, vec::Vec};
use core::num::NonZeroU32;

pub type Address = [u8; 20];
/// Carried native words; this helper does not validate or alter the timestamp.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Timestamp {
    pub date_word: NonZeroU32,
    pub seconds: u32,
    pub nanos: u32,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Position {
    /// Zero selects cross balance; any other byte selects isolated balance.
    pub margin_mode: u8,
    pub isolated_balance: i64,
    pub size: i64,
    pub funding_accumulators: [i64; 3],
}
#[derive(Clone, Debug)]
pub struct Record {
    pub asset: u64,
    pub payment: i64,
    pub size: i64,
    pub rate: f64,
    pub notional: i64,
    pub user: Address,
    pub time: Timestamp,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Largest {
    pub asset: u64,
    pub absolute_notional: u64,
    pub user: Address,
}
#[derive(Clone, Debug)]
pub struct Settlement {
    pub records: Vec<Record>,
    pub total_payment: i64,
    pub largest: Option<Largest>,
}
/// Owned diagnostics for native panic premises; not native error values or ABI.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Fault {
    OracleIndex { asset: u64 },
    NotionalRange { asset: u64 },
}

/// Apply 0x4205370's selected normal-return behavior over actual keyed state.
///
/// Rates are keyed by the full asset; oracle indices use asset % 10_000.
/// Iteration follows ascending unsigned asset keys. A missing time still checks
/// each applicable oracle index and signed notional, but emits/writes nothing.
/// Faults do not roll back earlier positions; native panic unwinding is excluded.
pub fn settle(
    positions: &mut BTreeMap<u64, Position>,
    rates: &BTreeMap<u64, f64>,
    oracle_prices: &[u64],
    cross_balance: &mut i64,
    user: Address,
    time: Option<Timestamp>,
) -> Result<Settlement, Fault> {
    let mut records = Vec::new();
    for (&asset, position) in positions.iter_mut() {
        let Some(&rate) = rates.get(&asset) else {
            continue;
        };
        if rate == 0.0 {
            continue;
        }
        // The native index check precedes the zero-position shortcut.
        let price = *oracle_prices
            .get((asset % 10_000) as usize)
            .ok_or(Fault::OracleIndex { asset })?;
        if position.size == 0 {
            continue;
        }
        let signed_price = i64::try_from(price).map_err(|_| Fault::NotionalRange { asset })?;
        let notional = signed_price
            .checked_mul(position.size)
            .ok_or(Fault::NotionalRange { asset })?;
        let Some(time) = time else { continue };
        let product = (notional as f64) * rate;
        // The native path first maps nonfinite products to zero, then clamps
        // finite products to +/-2^63 and performs a saturating signed cast.
        let converted = if product.is_finite() {
            product as i64
        } else {
            0
        };
        let payment = converted.saturating_neg();
        let charge = -payment; // payment cannot be i64::MIN.
        if position.margin_mode == 0 {
            *cross_balance = cross_balance.saturating_sub(charge);
        } else {
            position.isolated_balance = position.isolated_balance.saturating_sub(charge);
        }
        for accumulator in &mut position.funding_accumulators {
            *accumulator = accumulator.saturating_add(charge);
        }
        records.push(Record {
            asset,
            payment,
            size: position.size,
            rate,
            notional,
            user,
            time,
        });
    }
    let mut total_payment = 0i64;
    let mut largest: Option<Largest> = None;
    for (index, record) in records.iter().enumerate() {
        total_payment = if index == 0 {
            record.payment
        } else {
            total_payment.saturating_sub(record.payment.saturating_neg())
        };
        let absolute_notional = record.notional.unsigned_abs();
        if largest
            .as_ref()
            .is_none_or(|old| absolute_notional > old.absolute_notional)
        {
            largest = Some(Largest {
                asset: record.asset,
                absolute_notional,
                user,
            });
        }
    }
    Ok(Settlement {
        records,
        total_payment,
        largest,
    })
}
