//! Replica JSON response emission (`node115-replica-response-json`) and
//! `save_l4_snapshots.rs` configuration types for node #115.

pub mod spot;

use std::io::{self, Write};

pub use node115_replica_response_json::{write_response, Response as ReplicaResponse};

/// Options for `fileSnapshot` with `l4Snapshots` (`0x5f65cb` `includeUsers`, `includeTriggerOrders`).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct L4SnapshotOptions {
    pub include_users: bool,
    pub include_trigger_orders: bool,
}

/// Format a `ReplicaResponse` into a UTF-8 JSON `String` using `node115-replica-response-json`.
pub fn format_replica_response_json<T>(
    response: ReplicaResponse<'_, T>,
    write_entry: impl FnMut(&mut Vec<u8>, &T) -> io::Result<()>,
) -> io::Result<String> {
    let mut buf = Vec::new();
    write_response(&mut buf, response, write_entry)?;
    String::from_utf8(buf).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

/// Convenience helper for formatting a raw pre-encoded JSON entry slice.
pub fn write_raw_json_entry<W: Write>(out: &mut W, entry: &&str) -> io::Result<()> {
    out.write_all(entry.as_bytes())
}
