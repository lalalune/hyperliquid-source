//! Selected node115 SSTORE execution for resident, current-transaction warm slots.
//! Owns real logical storage and journal mutations. No captured code is executed.
#![forbid(unsafe_code)]
use std::collections::BTreeMap;

pub type Address = [u8; 20];
/// Native little-limb-order u256. Only exact equality/zero tests are needed here.
pub type Word = [u64; 4];
const ZERO: Word = [0; 4];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Slot {
    pub original: Word,
    pub current: Word,
    pub transaction_id: u32,
    /// True projects the selected loader's current-transaction, zero-cold-byte path.
    pub warm: bool,
}
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Account {
    pub flags: u8,
    pub slots: BTreeMap<Word, Slot>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Journal {
    Touched {
        address: Address,
    },
    StorageChanged {
        address: Address,
        key: Word,
        previous: Word,
    },
}
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Host {
    pub accounts: BTreeMap<Address, Account>,
    pub journal: Vec<Journal>,
    pub transaction_id: u32,
    pub reserve_enabled: bool,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Interpreter {
    pub address: Address,
    /// Top word is the key, followed by the new value.
    pub stack: Vec<Word>,
    pub is_static: bool,
    pub spec: u8,
    pub gas_remaining: u64,
    pub reserve: u64,
    pub host_spent: i64,
    pub refund: i64,
}

/// Logical projection of the selected gas-table fields, not a fork-name table.
#[derive(Clone, Copy, Debug)]
pub struct GasParams {
    pub fixed: u64,           // +0x98
    pub set: u64,             // +0xa0
    pub reset: u64,           // +0xa8
    pub clear_refund: i64,    // +0xb0
    pub sentry: u64,          // +0xc0
    pub restore_zero: i64,    // +0x138
    pub restore_nonzero: i64, // +0x140
    pub host_reserve: u64,    // +0x150
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Status {
    Success = 0,
    OutOfGas = 0x20,
    Sentry = 0x25,
    Static = 0x28,
    StackUnderflow = 0x2c,
}
/// Owned boundary/overflow categories, not native panic or provider-error ABIs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Fault {
    NonresidentAccount,
    NonresidentOrColdSlot,
    RefundNegation,
    RefundDeltaAddition,
    RefundAccumulation,
}

fn refund_delta(
    p: GasParams,
    modern: bool,
    original: Word,
    current: Word,
    new: Word,
) -> Result<i64, Fault> {
    if !modern {
        return Ok(if current != ZERO && new == ZERO {
            p.clear_refund
        } else {
            0
        });
    }
    if current == new {
        return Ok(0);
    }
    if original == current && new == ZERO {
        return Ok(p.clear_refund);
    }
    let mut delta = if original == ZERO {
        0
    } else if current == ZERO {
        p.clear_refund.checked_neg().ok_or(Fault::RefundNegation)?
    } else if new == ZERO {
        p.clear_refund
    } else {
        0
    };
    if original == new {
        let restore = if original == ZERO {
            p.restore_zero
        } else {
            p.restore_nonzero
        };
        delta = delta
            .checked_add(restore)
            .ok_or(Fault::RefundDeltaAddition)?;
    }
    Ok(delta)
}

/// Execute the selected warm-resident SSTORE path and retain its prefix effects.
///
/// Each reached account/slot must be present and the slot warm in the current
/// transaction. Other provider paths are outside this contract and return an
/// owned boundary fault. Successful allocations and valid logical containers
/// are premises. No rollback is applied: native storage/journal changes happen
/// before later gas, reserve and refund failures. A higher-level transaction
/// rollback is a separate operation and is not implemented here.
pub fn execute(i: &mut Interpreter, host: &mut Host, p: GasParams) -> Result<Status, Fault> {
    if i.is_static {
        return Ok(Status::Static);
    }
    if i.stack.len() < 2 {
        return Ok(Status::StackUnderflow);
    }
    let key = i.stack.pop().expect("checked two words");
    let new = i.stack.pop().expect("checked two words");
    if i.spec > 5 && i.gas_remaining <= p.sentry {
        return Ok(Status::Sentry);
    }
    let Some(after_fixed) = i.gas_remaining.checked_sub(p.fixed) else {
        return Ok(Status::OutOfGas);
    };
    i.gas_remaining = after_fixed;

    let account = host
        .accounts
        .get_mut(&i.address)
        .ok_or(Fault::NonresidentAccount)?;
    if account.flags & 4 == 0 {
        account.flags |= 4;
        host.journal.push(Journal::Touched { address: i.address });
    }
    let slot = account
        .slots
        .get_mut(&key)
        .ok_or(Fault::NonresidentOrColdSlot)?;
    if !slot.warm || slot.transaction_id != host.transaction_id {
        return Err(Fault::NonresidentOrColdSlot);
    }
    let original = slot.original;
    let current = slot.current;
    if current != new {
        slot.current = new;
        host.journal.push(Journal::StorageChanged {
            address: i.address,
            key,
            previous: current,
        });
    }
    let modern = i.spec >= 6;
    // The warm loader returns a zero cold flag, so there is no cold surcharge.
    let cost = if !modern {
        if current == ZERO && new != ZERO {
            p.set
        } else {
            p.reset
        }
    } else if current == new || original != current {
        0
    } else if original == ZERO {
        p.set
    } else {
        p.reset
    };
    let Some(after_cost) = i.gas_remaining.checked_sub(cost) else {
        return Ok(Status::OutOfGas);
    };
    i.gas_remaining = after_cost;

    if host.reserve_enabled && current != new {
        let amount = p.host_reserve;
        if original == current && original == ZERO {
            if i.reserve >= amount {
                i.reserve -= amount;
            } else {
                let needed = amount - i.reserve;
                let Some(remaining) = i.gas_remaining.checked_sub(needed) else {
                    return Ok(Status::OutOfGas);
                };
                i.gas_remaining = remaining;
                i.reserve = 0;
            }
            // Native arithmetic interprets these addition operands as i64 bits.
            i.host_spent = i.host_spent.saturating_add(amount as i64);
        }
        if original == new && original == ZERO && amount != 0 {
            i.host_spent = i.host_spent.saturating_sub(amount as i64);
            i.reserve = i.reserve.saturating_add(amount);
        }
    }
    let delta = refund_delta(p, modern, original, current, new)?;
    i.refund = i
        .refund
        .checked_add(delta)
        .ok_or(Fault::RefundAccumulation)?;
    Ok(Status::Success)
}
