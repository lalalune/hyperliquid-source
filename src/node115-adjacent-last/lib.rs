#![no_std]
#![forbid(unsafe_code)]
//! Exact adjacent-run compaction over opaque node115 record bytes.
//! The returned length is an owned safe API, not the original native ABI.

pub type Record = [u8; 32];
const KEY_BYTES: usize = 20;

fn same_key(left: &Record, right: &Record) -> bool {
    left[..KEY_BYTES] == right[..KEY_BYTES]
}

/// Keep the last complete row of each adjacent equal-key run. Nonadjacent
/// duplicates stay separate. The backing slice is not truncated or erased:
/// its tail follows the qualified initial-swap/duplicate-swap/distinct-copy
/// schedule. Caller sorting, record meaning and ownership remain unclaimed.
pub fn compact(records: &mut [Record]) -> usize {
    let len = records.len();
    if len < 2 {
        return len;
    }
    let mut first = 0;
    while first + 1 < len {
        if same_key(&records[first], &records[first + 1]) {
            break;
        }
        first += 1;
    }
    if first + 1 == len {
        return len;
    }
    records.swap(first, first + 1);
    let mut write = first + 1;
    for read in first + 2..len {
        if same_key(&records[write - 1], &records[read]) {
            records.swap(write - 1, read);
        } else {
            records[write] = records[read];
            write += 1;
        }
    }
    write
}
