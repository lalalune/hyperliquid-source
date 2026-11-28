//! Replica JSON response emission (`node115-replica-response-json`) and
//! `save_l4_snapshots.rs` configuration types for node #115.

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

/// Four fields written by the node #115 delegator summary JSON serializer.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct DelegatorSummary {
    pub delegated: f64,
    pub undelegated: f64,
    pub total_pending_withdrawal: f64,
    pub n_pending_withdrawals: u64,
}

// The fixed-precision Display template is shared with the order quantity writer.
// Keep one digit after the decimal point and canonicalize rounded negative zero.
fn staking_amount(value: f64) -> String {
    let mut text = format!("{value:.10}");
    let trimmed = text.trim_end_matches('0');
    let len = trimmed.len() + usize::from(trimmed.ends_with('.'));
    text.truncate(len);
    if text == "-0.0" {
        text.remove(0);
    }
    text
}

impl DelegatorSummary {
    /// Emit the compact JSON object from supplied staking state.
    pub fn write_json(&self, out: &mut impl Write) -> io::Result<()> {
        write!(
            out,
            r#"{{"delegated":"{}","undelegated":"{}","totalPendingWithdrawal":"{}","nPendingWithdrawals":{}}}"#,
            staking_amount(self.delegated),
            staking_amount(self.undelegated),
            staking_amount(self.total_pending_withdrawal),
            self.n_pending_withdrawals,
        )
    }
}

#[cfg(test)]
mod staking_tests {
    use super::*;

    #[test]
    fn preserves_wire_types_and_order() {
        let summary = DelegatorSummary {
            delegated: 12060.16529862,
            undelegated: -0.0,
            total_pending_withdrawal: 100.0,
            n_pending_withdrawals: u64::MAX,
        };
        let mut output = Vec::new();
        summary.write_json(&mut output).unwrap();
        assert_eq!(output, br#"{"delegated":"12060.16529862","undelegated":"0.0","totalPendingWithdrawal":"100.0","nPendingWithdrawals":18446744073709551615}"#);
    }

    #[test]
    fn rounds_before_normalizing() {
        for (input, expected) in [
            (1.23456789016, "1.2345678902"),
            (1.23456789014, "1.2345678901"),
            (1.0 / 2048.0, "0.0004882812"),
            (3.0 / 2048.0, "0.0014648438"),
            (-0.00000000004, "0.0"),
            (-0.00000000006, "-0.0000000001"),
            (999.99999999999, "1000.0"),
            (f64::INFINITY, "inf"),
            (f64::NEG_INFINITY, "-inf"),
            (f64::NAN, "NaN"),
        ] {
            assert_eq!(staking_amount(input), expected);
        }
    }
}
