//! Selected-digest extraction, registry remapping, queue draining, and the replay
//! comparison prefix observed in the pinned node115 artifact.
//!
//! This is a logical projection, not a quorum or signature verifier. Inputs are
//! already-populated tracker and registry maps. In particular, `selected` is
//! state to inspect, not evidence that a digest is authenticated. Timer policy,
//! vote admission, quorum selection, opaque signature values, the second native
//! collection, native container layout, and diagnostic effects are not modeled.
//! See RE-017-node115-digest-reference-handoff for the target binding and limits.
#![no_std]

extern crate alloc;

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

pub type Digest = [u8; 32];
pub type MemberId = [u8; 32];
pub type Address = [u8; 20];
pub type Registry = BTreeMap<u64, BTreeMap<MemberId, Address>>;

/// Projection of the tracker+0x18 height map's value. `Some` corresponds to
/// native selector byte +0x20 == 0 and the 32 bytes at +0x21.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HeightEntry {
    pub selected: Option<Digest>,
    /// Digest-keyed candidates, projected to the first collection's keys.
    pub candidates: BTreeMap<Digest, BTreeSet<MemberId>>,
}

/// Projection of a 0x68-byte emitted row: height +0, first collection +8,
/// digest +0x48. Opaque collection values and the second collection are omitted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReferenceRow {
    pub height: u64,
    pub digest: Digest,
    pub members: BTreeSet<Address>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TrackerProjection {
    pub heights: BTreeMap<u64, HeightEntry>,
    /// Logical rows already queued at native tracker+0x48.
    pub ready: Vec<ReferenceRow>,
}

impl TrackerProjection {
    /// Run the selected callback body for one supplied height. The caller must
    /// already have selected this height through the timer policy; this method
    /// does not decide whether the callback should run.
    ///
    /// 0x5377df0 selects the exact height and selected digest. 0x51520f0 remaps
    /// its first collection through 0x5b7a830 / 0x36ca940 using the current
    /// registry context. Missing memberships are dropped. Address duplicates
    /// collapse at 0x4dc0330 / 0x5b2d7c0; retained signature-value order is outside
    /// this projection. The row is queued even if no address survives.
    pub fn extract_selected(&mut self, height: u64, registry: &Registry, context: u64) {
        let Some(entry) = self.heights.get(&height) else {
            return;
        };
        let Some(digest) = entry.selected else {
            return;
        };
        let Some(ids) = entry.candidates.get(&digest) else {
            return;
        };
        let members = ids
            .iter()
            .filter_map(|id| registry.get(&context)?.get(id).copied())
            .collect();
        self.ready.push(ReferenceRow {
            height,
            digest,
            members,
        });
    }

    /// 0x5afa030 after its timer callback returns: take the queue, empty it,
    /// and retain rows with nonempty first collections in their original order.
    pub fn drain_ready(&mut self) -> Vec<ReferenceRow> {
        core::mem::take(&mut self.ready)
            .into_iter()
            .filter(|row| !row.members.is_empty())
            .collect()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Comparison {
    /// No local history entry at this row's exact key. This is a skip, not
    /// successful authentication or evidence that the reference was rejected.
    MissingLocal,
    Equal,
    /// The selected native path enters the mismatch diagnostic. This result
    /// does not model diagnostic I/O, process termination, or recovery behavior.
    Mismatch,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Observation {
    pub height: u64,
    pub incoming: Digest,
    pub local: Option<Digest>,
    pub comparison: Comparison,
}

/// Observe the comparison prefix at 0x5a04e40 after the entire batch has been
/// sent to the +0x280 sink. Stop at the first mismatch diagnostic; later
/// comparisons and subsequent pruning are excluded.
///
/// There is deliberately no current-height or authentication argument: this
/// boundary compares the row's exact key and all 32 digest bytes. It does not
/// establish how the selected tracker state was admitted.
pub fn compare_prefix(
    rows: &[ReferenceRow],
    local_history: &BTreeMap<u64, Digest>,
) -> Vec<Observation> {
    let mut observations = Vec::new();
    for row in rows {
        let local = local_history.get(&row.height).copied();
        let comparison = match local {
            None => Comparison::MissingLocal,
            Some(value) if value == row.digest => Comparison::Equal,
            Some(_) => Comparison::Mismatch,
        };
        observations.push(Observation {
            height: row.height,
            incoming: row.digest,
            local,
            comparison,
        });
        if comparison == Comparison::Mismatch {
            break;
        }
    }
    observations
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayHandoff {
    /// Every row is sent to the sink before the comparison loop starts, even
    /// when an early mismatch later prevents comparison of the remaining rows.
    pub sink_pairs: Vec<(u64, Digest)>,
    pub comparisons: Vec<Observation>,
}

/// Ordered logical effects of the selected handoff, assuming all sink calls
/// return normally. The sink's encoding, clock, and I/O effects are excluded.
pub fn replay_handoff(
    rows: &[ReferenceRow],
    local_history: &BTreeMap<u64, Digest>,
) -> ReplayHandoff {
    let sink_pairs = rows.iter().map(|row| (row.height, row.digest)).collect();
    ReplayHandoff {
        sink_pairs,
        comparisons: compare_prefix(rows, local_history),
    }
}
