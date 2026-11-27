#![forbid(unsafe_code)]
//! Clean-room integrated `info_server` (`info-api`) crate for Hyperliquid node #115.
//!
//! Target ELF: `artifacts/node/115/hl-node`
//! SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
//!
//! Joins the Stream F Info API micro-crates (`node115-json-string-scanner`,
//! `node115-json-error-position`, `node115-replica-response-json`,
//! `node115-risk-candidate-scan`, and the `node115-position-integer` prefix logic)
//! with the complete 55-variant `InfoRequest` schema, 2-variant `FileSnapshotRequest`
//! schema, and HTTP handler / snapshot-guard invariants statically observed in #115.

pub mod position;
pub mod request;
pub mod response;
pub mod router;

pub use global_constants;
pub use node115_json_error_position;
pub use node115_json_string_scanner;
pub use node115_replica_response_json;
pub use node115_risk_candidate_scan;

/// All 7 `info_server/src/*.rs` source paths observed in node #115 `.rodata`.
pub const INFO_SERVER_SOURCE_PATHS: [&str; 7] = [
    "info_server/src/abci_state_info_handler.rs",
    "info_server/src/f_types/position.rs",
    "info_server/src/handle_request.rs",
    "info_server/src/handler.rs",
    "info_server/src/router.rs",
    "info_server/src/save_l4_snapshots.rs",
    "info_server/src/user_ip.rs",
];

/// Total `.data.rel.ro` panic `Location` records referencing `info_server/src/*.rs` in node #115.
pub const INFO_SERVER_PANIC_LOCATION_COUNT: usize = 43;
