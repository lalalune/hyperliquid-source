//! Owned keyed-state implementation of the selected leverage aggregate update.
#![no_std]
#![forbid(unsafe_code)]
extern crate alloc;
use alloc::collections::BTreeMap;
pub type Address = [u8; 20];
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Row {
    pub price: u64,
    /// Native +0x08 and +0x10, respectively.
    pub side_values: [u64; 2],
    /// Native +0x18 and +0x20, respectively.
    pub side_quantities: [u64; 2],
    pub size: i64,
    pub leverage: u32,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct User {
    pub assets: BTreeMap<u64, Row>,
    pub aggregate: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Fault {
    OldLeverageZero,
    NewLeverageZero,
}
fn selected_value(row: &Row) -> u64 {
    let side = usize::from(row.size <= 0);
    let base = row.side_values[side];
    let opposite = row.side_values[1 - side];
    let quantity = row.side_quantities[1 - side];
    if quantity == 0 || quantity > opposite {
        return base;
    }
    let magnitude = row.size.unsigned_abs();
    let Some(notional) = magnitude
        .checked_mul(row.price)
        .filter(|&x| x < i64::MAX as u64)
    else {
        return base;
    };
    let Some(remaining_quantity) = quantity.checked_sub(magnitude.saturating_mul(2)) else {
        return base;
    };
    let Some(remaining_value) = opposite.checked_sub(notional * 2) else {
        return base;
    };
    let Some(candidate) = (opposite / quantity)
        .checked_mul(remaining_quantity)
        .filter(|&x| x < i64::MAX as u64)
    else {
        return base;
    };
    base.max(remaining_value.min(candidate))
}
/// Apply the complete selected normal-return behavior of 0x44831a0.
///
/// Missing keys and unchanged leverage do nothing. Divisions use the same
/// selected integer value. Aggregate subtraction and addition saturate
/// separately. Faults are owned diagnostics for excluded native division-fault
/// premises; a new zero leverage is written before its fault, as in the target.
pub fn update(
    users: &mut BTreeMap<Address, User>,
    user: &Address,
    asset: u64,
    leverage: u32,
) -> Result<(), Fault> {
    let Some(user) = users.get_mut(user) else {
        return Ok(());
    };
    let Some(row) = user.assets.get_mut(&asset) else {
        return Ok(());
    };
    if row.leverage == leverage {
        return Ok(());
    }
    let value = selected_value(row);
    let old = value
        .checked_div(u64::from(row.leverage))
        .ok_or(Fault::OldLeverageZero)?;
    row.leverage = leverage;
    let new = value
        .checked_div(u64::from(leverage))
        .ok_or(Fault::NewLeverageZero)?;
    user.aggregate = user.aggregate.saturating_sub(old).saturating_add(new);
    Ok(())
}
