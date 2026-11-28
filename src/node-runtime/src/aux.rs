//! Auxiliary output streams, biased priority channel, group/sequence latency sampler,
//! and sync runtime guard matching node #115:
//! - `node/src/aux.rs` (`0x51cf360..0x51d0f70`, `Location 0x64a3660` L262:13)
//! - `node/src/channel.rs` (`0x2e071c0..0x2e075e8`, `0x5a71040..0x5a7172a`)
//! - `node/src/group_and_seq_sampler.rs` (`0x5b298d0..0x5b2a121`, `0x5b2a130..0x5b2aa61`)
//! - `node/src/utils.rs` (`0x2ae1690..0x2ae27b2`)

use std::cell::Cell;
use std::collections::{BTreeMap, VecDeque};
use std::time::Duration;

use crate::error::NodeError;

/// Exact 10 auxiliary output stream directory/topic names observed in `node/src/aux.rs`
/// (`0x51cf360..0x51d0f70`, `.rodata 0x91fcc0..0x91fd5e` & `0x91c33c`).
pub const AUX_OUTPUT_STREAMS: [&str; 10] = [
    "node_trades",
    "node_fills",
    "node_twap_statuses",
    "node_raw_book_diffs",
    "node_order_statuses",
    "misc_events",
    "hip3_oracle_updates",
    "system_and_core_writer_actions",
    "evm_block_and_receipts",
    "dex_user_clearinghouse_states",
];

/// Mutual-exclusion invariant panic string at `0x51d0aba -> .rodata 0x91fd5f`.
pub const AUX_BATCH_VS_STREAM_CONFLICT_MSG: &str =
    "cannot set both batch_by_block and stream_with_block_info";

/// Nested-runtime guard message observed in `node/src/utils.rs` (`0x2ae21b6 -> .rodata 0x60692e`).
pub const NESTED_RUNTIME_ERROR_MSG: &str = "Cannot start a runtime from within a runtime.";

/// Auxiliary stream output configuration matching `node/src/aux.rs`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AuxStreamConfig {
    pub batch_by_block: bool,
    pub stream_with_block_info: bool,
    pub enabled_streams: Vec<&'static str>,
}

impl AuxStreamConfig {
    pub fn validate(&self) -> Result<(), NodeError> {
        if self.batch_by_block && self.stream_with_block_info {
            return Err(NodeError::Config(
                AUX_BATCH_VS_STREAM_CONFLICT_MSG.to_owned(),
            ));
        }
        for &stream in &self.enabled_streams {
            if !AUX_OUTPUT_STREAMS.contains(&stream) {
                return Err(NodeError::Config(format!("unknown aux stream: {stream}")));
            }
        }
        Ok(())
    }
}

/// Biased dual-priority queue matching `node/src/channel.rs` (`0x2e071c0..0x2e075e8`):
/// always drains high-priority messages before normal-priority messages.
#[derive(Clone, Debug)]
pub struct PriorityChannel<T> {
    high: VecDeque<T>,
    normal: VecDeque<T>,
    capacity: usize,
}

impl<T> PriorityChannel<T> {
    pub fn new(capacity: usize) -> Self {
        let cap = capacity.max(1);
        Self {
            high: VecDeque::with_capacity(cap),
            normal: VecDeque::with_capacity(cap),
            capacity: cap,
        }
    }

    pub fn try_send_high(&mut self, item: T) -> Result<(), T> {
        if self.high.len() >= self.capacity {
            return Err(item);
        }
        self.high.push_back(item);
        Ok(())
    }

    pub fn try_send_normal(&mut self, item: T) -> Result<(), T> {
        if self.normal.len() >= self.capacity {
            return Err(item);
        }
        self.normal.push_back(item);
        Ok(())
    }

    /// Biased receive: high-priority items are always returned before normal-priority items.
    pub fn try_recv(&mut self) -> Option<T> {
        self.high.pop_front().or_else(|| self.normal.pop_front())
    }

    pub fn len(&self) -> usize {
        self.high.len() + self.normal.len()
    }

    pub fn is_empty(&self) -> bool {
        self.high.is_empty() && self.normal.is_empty()
    }
}

/// Per-group sequence latency sampler matching `node/src/group_and_seq_sampler.rs`
/// (`0x5b298d0..0x5b2a121`): converts nanoseconds via `/ 1e9` (`0x458d50`) and clamps
/// `+inf` (`0x459010` at `0x5b29977`) to `0.0`.
#[derive(Clone, Debug, Default)]
pub struct GroupAndSeqSampler {
    stats_by_group: BTreeMap<u64, GroupSeqStats>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct GroupSeqStats {
    pub count: u64,
    pub total_secs: f64,
    pub max_secs: f64,
}

impl GroupAndSeqSampler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Map non-finite or negative external samples to zero.
    pub fn sanitize_elapsed_secs(elapsed_secs: f64) -> f64 {
        if elapsed_secs == f64::INFINITY || elapsed_secs.is_nan() || elapsed_secs < 0.0 {
            0.0
        } else {
            elapsed_secs
        }
    }

    pub fn record_nanos(&mut self, group_id: u64, elapsed_nanos: u64) {
        // Both node #115 samplers divide the subsecond part before adding whole seconds.
        self.record_secs(group_id, Duration::from_nanos(elapsed_nanos).as_secs_f64());
    }

    pub fn record_secs(&mut self, group_id: u64, elapsed_secs: f64) {
        let secs = Self::sanitize_elapsed_secs(elapsed_secs);
        let entry = self.stats_by_group.entry(group_id).or_default();
        entry.count += 1;
        entry.total_secs += secs;
        if secs > entry.max_secs {
            entry.max_secs = secs;
        }
    }

    pub fn stats(&self, group_id: u64) -> Option<GroupSeqStats> {
        self.stats_by_group.get(&group_id).copied()
    }
}

thread_local! {
    static IN_RUNTIME_BLOCK_ON: Cell<bool> = const { Cell::new(false) };
}

/// Synchronous runtime entrypoint guard matching `node/src/utils.rs` (`0x2ae1690..0x2ae27b2`):
/// rejects nested entry with `"Cannot start a runtime from within a runtime."` (`0x60692e`).
pub fn block_on_sync<T, F: FnOnce() -> T>(f: F) -> Result<T, NodeError> {
    let already_entered = IN_RUNTIME_BLOCK_ON.with(|flag| {
        if flag.get() {
            true
        } else {
            flag.set(true);
            false
        }
    });
    if already_entered {
        return Err(NodeError::Config(NESTED_RUNTIME_ERROR_MSG.to_owned()));
    }
    struct ResetGuard;
    impl Drop for ResetGuard {
        fn drop(&mut self) {
            IN_RUNTIME_BLOCK_ON.with(|flag| flag.set(false));
        }
    }
    let _guard = ResetGuard;
    Ok(f())
}
