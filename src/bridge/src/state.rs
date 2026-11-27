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
