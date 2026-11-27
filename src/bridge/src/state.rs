//! Node #115 `l1/src/bridge2.rs` state metadata and withdrawal mutation bridge.
//!
//! Grounded in `bridge-state-serializer-115` (15 serialized members across
//! `0x291e600`, `0x44d2370`, `0x5afb950`) and `RE-005-node115-bridge-request-mutation`
//! (`0x44d83f0`, panic diagnostic `"bridge2 withdrawal balance bug"` at
//! `l1/src/bridge2.rs:145:95` and `147:68`).

/// Number of serialized members in the node #115 `Bridge2` state struct
/// (`bridge-state-serializer-115`, `edx = 0xf`).
pub const BRIDGE2_SERIALIZED_FIELD_COUNT: usize = 15;

/// Named keys directly observed in the node #115 `Bridge2` state serializers
/// (`0x291e600`, `0x44d2370`, `0x5afb950`).
pub const BRIDGE2_SERIALIZED_NAMED_KEYS: [&str; 8] = [
    "eth_id_to_deposit_votes",
    "finished_deposits_data",
    "dvp",
    "dvpd",
    "dvs",
    "bal",
    "last_pruned_deposit_block_number",
    "oaw",
];

/// Complete 15-field `Bridge2` serde schema names observed in `.rodata` `0x7d09dd..0x7d0a99`
/// and `bridge-state-serializer-115` (`0x291e600`, `0x44d2370`, `0x5afb950`).
pub const BRIDGE2_ALL_15_FIELD_NAMES: [&str; BRIDGE2_SERIALIZED_FIELD_COUNT] = [
    "eth_id_to_deposit_votes",
    "finished_deposits_data",
    "dvp",
    "dvpd",
    "dvs",
    "lfd",
    "withdrawal_signatures",
    "withdrawal_finalized_votes",
    "finished_withdrawal_to_time",
    "validator_set_signatures",
    "validator_set_finalized_votes",
    "bal",
    "last_pruned_deposit_block_number",
    "oaw",
    "r",
];

/// Exact panic message emitted at `0x44d8511` (`l1/src/bridge2.rs:147:68`, `.rodata` `0x7d30e2`, len 30)
/// when subtracting a withdrawal amount underflows `Bridge2::bal` (`[rbx + 0x1c8]`).
pub const BRIDGE2_WITHDRAWAL_BALANCE_BUG_MSG: &str = "bridge2 withdrawal balance bug";

/// Ok discriminant word (`0x1a2`) checked by `0x44d8448`, `0x44d7b95`, and `0x44d7f64`.
pub const BRIDGE2_OK_DISCRIMINANT: u16 = 0x1a2;

/// Element byte stride (`0x68` = 104 B) of the `finished_deposits_data` ring at `Bridge2 + 0x160..+0x178`
/// (`0x44d7d4b` and `bridge-state-serializer-115`).
pub const BRIDGE2_DEPOSIT_RING_STRIDE: usize = 0x68;

/// Checked withdrawal debit modeling `0x44d8454..0x44d8511` (`sub rax, r14; jb panic`).
pub fn debit_bridge2_balance(balance: &mut u64, amount: u64) -> Result<u64, &'static str> {
    match balance.checked_sub(amount) {
        Some(updated) => {
            *balance = updated;
            Ok(updated)
        }
        None => Err(BRIDGE2_WITHDRAWAL_BALANCE_BUG_MSG),
    }
}
