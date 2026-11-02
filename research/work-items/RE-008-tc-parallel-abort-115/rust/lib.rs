//! Safe value projections, not the native pointer ABI or a scheduler.
//!
//! See PROOF.md for ordinary-return, defined-byte, disjoint-storage and opaque
//! helper premises. Supplied observations do not establish their reachability.
#![forbid(unsafe_code)]

pub const SUCCESS: u8 = 0x2e;
pub const STOP: u8 = 0x2f;
pub type Record = [u8; 72];
pub type DropRequest = (u64, u64, u64);

fn word(image: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(image[offset..offset + 8].try_into().unwrap())
}

/// Inlined cleanup requests for a discarded error. Never frees memory.
pub fn cleanup(error: &Record) -> Vec<DropRequest> {
    let mut requests = Vec::new();
    let mut descriptor = |offset| {
        let length = word(error, offset);
        if length != 0 {
            requests.push((word(error, offset + 8), length, 0));
        }
    };
    match error[0] {
        0x10 => {
            descriptor(8);
            descriptor(32);
        }
        0x13 | 0x20 => descriptor(8),
        _ => {}
    }
    requests
}

#[derive(Debug, PartialEq, Eq)]
pub struct Merge {
    pub output: Record,
    /// 0: left error; 1: right error; 2: both success.
    pub selection: u8,
    pub cleanup: Vec<DropRequest>,
    /// O = output stored; D = one ordinary cleanup request, in native order.
    pub trace: String,
}

pub fn merge(mut seed: Record, left: Record, right: Record) -> Merge {
    let selection;
    let mut drops = Vec::new();
    if left[0] != SUCCESS {
        seed = left;
        selection = 0;
        if right[0] != SUCCESS {
            drops = cleanup(&right);
        }
    } else if right[0] != SUCCESS {
        seed = right;
        selection = 1;
    } else {
        seed[0] = SUCCESS;
        selection = 2;
    }
    let trace = format!("O{}", "D".repeat(drops.len()));
    Merge { output: seed, selection, cleanup: drops, trace }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Fold {
    pub folder: [u8; 88],
    pub consumed: usize,
    pub reads: usize,
    pub writes: usize,
    /// 0 exhaustion; 1 raw STOP; 2 error; 3 observed cancellation.
    pub reason: u8,
    pub cursor: u64,
    pub cleanup: Vec<DropRequest>,
    /// C callback; D cleanup; W flag=1; S folder store; R flag read; O output copy.
    pub trace: String,
}

/// `after` supplies the byte actually observed after each successful reduction.
/// Numeric cursor arithmetic is not admission of wrapped native memory spans.
pub fn fold(mut folder: [u8; 88], start: u64, stride: u64,
            outcomes: &[Record], after: &[u8]) -> Option<Fold> {
    if outcomes.len() != after.len() || (stride != 16 && stride != 104) {
        return None;
    }
    let mut result = Fold { folder, consumed: 0, reads: 0, writes: 0, reason: 0,
                            cursor: start, cleanup: Vec::new(), trace: String::new() };
    for (next, &observed) in outcomes.iter().zip(after) {
        result.consumed += 1;
        result.cursor = result.cursor.wrapping_add(stride);
        result.trace.push('C');
        if next[0] == STOP {
            result.reason = 1;
            break;
        }
        if folder[0] == SUCCESS {
            if next[0] != SUCCESS {
                folder[..72].copy_from_slice(next);
            }
        } else if next[0] != SUCCESS {
            let drops = cleanup(next);
            result.trace.push_str(&"D".repeat(drops.len()));
            result.cleanup.extend(drops);
        }
        if folder[0] != SUCCESS {
            result.writes += 1;
            result.trace.push('W');
        }
        result.trace.push('S');
        if folder[0] != SUCCESS {
            result.reason = 2;
            break;
        }
        result.reads += 1;
        result.trace.push('R');
        if observed != 0 {
            result.reason = 3;
            break;
        }
    }
    result.trace.push('O');
    result.folder = folder;
    Some(result)
}

#[derive(Debug, PartialEq, Eq)]
pub struct Plan {
    /// 0 abort; 1 local; 2 split; 3 producer subtraction underflow boundary.
    pub region: u8,
    pub half: u64,
    pub budget: u64,
    pub right_count: u64,
    pub right_start: u64,
    pub local_end: u64,
    pub worker_observed: bool,
}

#[allow(clippy::too_many_arguments)]
pub fn plan(stride: u64, cancel: u8, logical: u64, count: u64, migrated: u8,
            budget: u64, minimum: u64, workers: u64, start: u64) -> Option<Plan> {
    if stride != 16 && stride != 104 { return None; }
    let mut p = Plan { region: 0, half: 0, budget: 0, right_count: 0,
                       right_start: 0, local_end: 0, worker_observed: false };
    if cancel != 0 { return Some(p); }
    p.half = logical >> 1;
    if p.half < minimum || (migrated == 0 && budget == 0) {
        p.region = 1;
        p.local_end = start.wrapping_add(count.wrapping_mul(stride));
        return Some(p);
    }
    p.budget = budget >> 1;
    if migrated != 0 {
        p.worker_observed = true;
        p.budget = p.budget.max(workers);
    }
    let Some(right) = count.checked_sub(p.half) else {
        p.region = 3;
        return Some(p);
    };
    p.region = 2;
    p.right_count = right;
    p.right_start = start.wrapping_add(p.half.wrapping_mul(stride));
    Some(p)
}

#[derive(Debug, PartialEq, Eq)]
pub struct Closure {
    /// Only these 52 bytes are initialized; the 56-byte allocation's tail is unclaimed.
    pub initialized: [u8; 52],
    pub output: Record,
    /// Message tag, supplied allocation address, key, value+8, validator snapshot.
    pub call_values: [u64; 5],
    pub rax: u64,
}

#[allow(clippy::too_many_arguments)]
pub fn closure(prefix: [u8; 16], cert_round: u64, value: u64, key: [u8; 20],
               value_address: u64, key_address: u64, snapshot_address: u64,
               heap_address: u64, returned_al: u8, output_address: u64,
               mut seed: Record) -> Closure {
    let mut initialized = [0; 52];
    initialized[..16].copy_from_slice(&prefix);
    initialized[16..24].copy_from_slice(&cert_round.to_le_bytes());
    initialized[24..32].copy_from_slice(&value.to_le_bytes());
    initialized[32..].copy_from_slice(&key);
    seed[0] = if returned_al != 0 { SUCCESS } else { 9 };
    Closure { initialized, output: seed,
              call_values: [2, heap_address, key_address, value_address.wrapping_add(8), snapshot_address],
              rax: output_address }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Admission {
    pub output: Record,
    pub trace: String,
    pub collection_cleanup: bool,
    pub rax: u64,
}

/// Supplied rows are the actual finite enumeration. Helper results and ordinary
/// cleanup are premises, not a replacement for history/quorum/QC/crypto routines.
#[allow(clippy::too_many_arguments)]
pub fn admission(mut seed: Record, history: Record, collection: Record,
                 nested: Record, parallel_output: Record, rows: &[u64],
                 wanted: u64, round: u64, quorum_al: u8, output_address: u64) -> Admission {
    let mut trace = String::from("H");
    let mut drop_collection = false;
    if history[0] != SUCCESS {
        seed = history;
    } else {
        trace.push('C');
        if collection[0] != SUCCESS {
            seed = collection;
        } else {
            drop_collection = true;
            trace.push('I');
            let mut maximum = None;
            for &row in rows {
                maximum = Some(maximum.map_or(row, |old: u64| old.max(row)));
            }
            match maximum {
                None => seed[0] = 8,
                Some(m) if m != wanted || m >= round => seed[0] = 11,
                Some(_) => {
                    trace.push('Q');
                    if quorum_al == 0 {
                        seed[0] = 8;
                    } else {
                        trace.push('N');
                        if nested[0] != SUCCESS {
                            seed = nested;
                        } else {
                            trace.push_str("VP");
                            seed = parallel_output;
                        }
                    }
                }
            }
            trace.push('D');
        }
    }
    Admission { output: seed, trace, collection_cleanup: drop_collection, rax: output_address }
}

/// Value observations of entry dispatch / flat-wrapper setup / outer TLS route.
/// The final capacity*16 value alone does not describe whether deallocation is
/// called (native tests capacity != 0 before multiplying, even if size wraps).
#[allow(clippy::too_many_arguments)]
pub fn entry(representation: u64, capacity: u64, count: u64, start: u64,
             workers: u64, tls_before: u64, tls_after: u64, tls_pool: u64,
             global_pool: u64) -> [u64; 8] {
    if representation != 0 {
        let route = if tls_before != 0 { 0 } else if tls_after == 0 { 1 }
                    else if tls_pool != global_pool { 2 } else { 0 };
        [1, 0, route, u64::from(tls_before == 0), 0, 0, 0, 0]
    } else if capacity < count {
        [0, 0, 3, 0, 0, 0, 0, 0]
    } else {
        [0, 0, 4, 1, count, workers, start, capacity.wrapping_mul(16)]
    }
}
