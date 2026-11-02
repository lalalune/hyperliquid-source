#![forbid(unsafe_code)]
//! Apply one explicitly supplied node 94 returned record stream to active values.
//!
//! This is a chosen owned-value API, not the captured ABI or B-tree layout.
//! The binary-backed relation ends at host record-loop exit `0x222b480` and
//! requires the native valid-storage and allocator/copy/frame premises in the
//! evidence packet. Rust allocation/panic/rollback behavior, scheduling, outer
//! dex pairing and economic interpretation are outside this projection.

use std::collections::BTreeMap;

/// Three raw u64 values from an active returned record, without a native layout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record {
    pub key: u64,
    pub tag: u64,
    pub payload: u64,
}

/// Update the two active-value maps from the prefix before the first full tag 2.
///
/// Every other even tag appends its unchanged payload bits to the key's sample
/// vector, creating an empty vector first when absent. Odd tags insert or
/// replace a fallback value only when `dex_byte == 3`. Existing unrelated
/// entries and record inputs are preserved. No payload is converted to a float.
///
/// The value relation requires finite representable state and successful Rust
/// allocation. Allocation failure, panic, abort, partial state and rollback are
/// not reconstructed error results. This function performs no external I/O.
pub fn apply_returned_records(
    samples: &mut BTreeMap<u64, Vec<u64>>,
    fallbacks: &mut BTreeMap<u64, u64>,
    dex_byte: u8,
    records: &[Record],
) {
    for record in records {
        if record.tag == 2 {
            break;
        }
        if record.tag & 1 == 0 {
            samples.entry(record.key).or_default().push(record.payload);
        } else if dex_byte == 3 {
            fallbacks.insert(record.key, record.payload);
        }
    }
}
