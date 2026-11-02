//! Conditional value projection of node94's TC fold, bridge decision and merge.
//!
//! This is an analysis component, not a Rayon replacement or a signature verifier.
//! A call observation supplies the verifier's raw result and shared-byte value
//! after that call. It does not authenticate either observation or predict which
//! observations a concurrent execution can produce. See ../PROOF.md for the
//! native domain, defined-byte premise and unclaimed allocator/scheduler effects.
#![no_std]
#![forbid(unsafe_code)]

pub const SUCCESS: u64 = 0x8000_0000_0000_002a;
pub const STOP: u64 = SUCCESS + 1;

fn tag(record: &[u8]) -> u64 {
    u64::from_le_bytes(record[..8].try_into().expect("fixed record"))
}

#[derive(Clone, Copy)]
pub struct Observation {
    pub result: [u8; 80],
    pub flag_after_call: u8,
}

#[derive(Debug, PartialEq, Eq)]
pub struct FoldResult {
    pub folder: [u8; 96],
    pub flag: u8,
    pub calls: usize,
    pub flag_reads: usize,
    pub flag_writes: usize,
    /// 0 exhausted, 1 extra marker, 2 local error, 3 observed cancellation.
    pub stop: u8,
    /// Raw argument delegated to the native drop boundary; no drop is executed.
    pub dropped: Option<[u8; 80]>,
}

/// Project the ordinary local fold over a valid 184-byte-row span.
///
/// Entry cancellation is checked by the separate bridge, not by this leaf.
/// The leaf invokes the verifier for its first row even when `initial_flag`
/// is nonzero. The opaque final 16 folder bytes are preserved.
pub fn fold(folder: [u8; 96], initial_flag: u8, items: &[Observation]) -> FoldResult {
    let mut out = FoldResult {
        folder,
        flag: initial_flag,
        calls: 0,
        flag_reads: 0,
        flag_writes: 0,
        stop: 0,
        dropped: None,
    };
    for item in items {
        out.calls += 1;
        out.flag = item.flag_after_call;
        let incoming = tag(&item.result);
        if incoming == STOP {
            out.stop = 1;
            break;
        }
        let previous = tag(&out.folder);
        if previous != SUCCESS {
            if incoming != SUCCESS {
                out.dropped = Some(item.result);
            }
        } else if incoming != SUCCESS {
            out.folder[..80].copy_from_slice(&item.result);
        }
        if tag(&out.folder) != SUCCESS {
            out.flag = 1;
            out.flag_writes += 1;
            out.stop = 2;
            break;
        }
        out.flag_reads += 1;
        if out.flag != 0 {
            out.stop = 3;
            break;
        }
    }
    out
}

#[derive(Debug, PartialEq, Eq)]
pub struct MergeResult {
    pub output: [u8; 80],
    pub written_bytes: u8,
    /// Delegation follows the output write; no allocator effect is reproduced.
    pub dropped: Option<[u8; 80]>,
}

/// Merge already supplied child results. This does not choose their schedule.
/// Both-success writes just eight bytes; two errors select left and drop right.
pub fn merge(mut output: [u8; 80], left: [u8; 80], right: [u8; 80]) -> MergeResult {
    let left_ok = tag(&left) == SUCCESS;
    let right_ok = tag(&right) == SUCCESS;
    let written_bytes;
    if left_ok && right_ok {
        output[..8].copy_from_slice(&SUCCESS.to_le_bytes());
        written_bytes = 8;
    } else {
        output = if left_ok { right } else { left };
        written_bytes = 80;
    }
    MergeResult {
        output,
        written_bytes,
        dropped: if !left_ok && !right_ok {
            Some(right)
        } else {
            None
        },
    }
}

#[derive(Clone, Copy)]
pub struct BridgeInput {
    pub logical_len: u64,
    pub producer_len: u64,
    pub minimum: u64,
    pub splits: u64,
    pub migrated: u8,
    pub observed_cancel: u8,
    pub observed_threads: u64,
}

/// Return [kind, midpoint, remainder, next_splits, byte_delta, thread_reads].
/// Kind 0 cancelled, 1 local fold, 2 split, 3 native underflow-panic branch.
/// Fields without a native value observation on that path are reported as zero.
/// The byte delta is numerical wrapping arithmetic, not pointer dereferencing.
pub fn plan(input: BridgeInput) -> [u64; 6] {
    if input.observed_cancel != 0 {
        return [0; 6];
    }
    let mid = input.logical_len >> 1;
    if mid < input.minimum || (input.migrated == 0 && input.splits == 0) {
        return [1, 0, 0, 0, input.producer_len.wrapping_mul(184), 0];
    }
    let mut next_splits = input.splits >> 1;
    let thread_reads = u64::from(input.migrated != 0);
    if input.migrated != 0 {
        next_splits = next_splits.max(input.observed_threads);
    }
    match input.producer_len.checked_sub(mid) {
        Some(rest) => [
            2,
            mid,
            rest,
            next_splits,
            mid.wrapping_mul(184),
            thread_reads,
        ],
        None => [3, mid, 0, next_splits, 0, thread_reads],
    }
}
