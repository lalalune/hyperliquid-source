#![no_std]
#![forbid(unsafe_code)]

//! Safe slice projection of node #94's complete 0x52ca970..0x52ca9e3 leaf.

/// Return the raw u64 index selected by the captured leaf's decisions.
///
/// `key >= limit` returns `entries.len() - 1` modulo 2^64, including u64::MAX
/// for an empty slice. That shortcut takes precedence over the empty search.
/// Otherwise the midpoint decisions are preserved even for unsorted entries.
/// For nondecreasing entries this is a lower-bound index, possibly the length;
/// an unsorted slice has only the documented decision-path interpretation.
///
/// This projects an ordinary valid contiguous qword span into a Rust slice.
/// On supported 32/64-bit hosts its valid byte length is below 2^63. Original
/// malformed, negative, non-qword-aligned or wrapping pointer differences,
/// volatile/concurrent memory, the descriptor ABI and the limit's meaning are
/// outside this API. No captured node code runs and no memory is modified.
pub fn raw_index(entries: &[u64], key: u64, limit: u64) -> u64 {
    if key >= limit {
        return (entries.len() as u64).wrapping_sub(1);
    }
    let mut low = 0;
    let mut high = entries.len();
    while low < high {
        let mid = low + (high - low) / 2;
        if entries[mid] < key {
            low = mid + 1;
        } else {
            high = mid;
        }
    }
    low as u64
}
