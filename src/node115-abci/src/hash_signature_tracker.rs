//! Node #115 `l1/src/abci/hash_signature_tracker.rs` full logical tracker uniting:
//! - Running unsigned max watermark (`tracker + 0x80`, `0x27605e4`, `0x5afb227`)
//! - Seal marker (`tracker + 0x90`, `0x2760627`)
//! - Saturating prune window `50_000` (`0xc350`, `0x276063a`, `0x5afb284`)
//! - Pending-map cutoff `1_000` (`0x3e8`, `0x5afa04e`)
//! - Pre-insertion admission (`node115-digest-vote-admission`)
//! - Two-gate support transition (`node115-digest-support-gate`)
//! - Extraction, registry remap, drain (`node115-digest-reference-handoff`)
//! - Quorum sink JSON serialization (`node115-quorum-line`)

use std::collections::{BTreeMap, BTreeSet};

use node115_abci_checkpoint_replay_fixture::{
    ACTION_TAG_ABCI_DIGEST_VOTE, ExternalDigestVote, SupportContext, VOTE_HEIGHT_EXCLUSIVE_LIMIT,
};
use node115_digest_reference_handoff::{
    Digest, MemberId, ReferenceRow, Registry, TrackerProjection,
};
use node115_digest_support_gate::supports;
use node115_digest_vote_admission::{Admission, Snapshot as AdmissionSnapshot, Voter, admission_for};
use node115_quorum_line::quorum_log_line;

/// Saturating prune window observed at `0x276063a` and `0x5afb284` (`0xc350`).
pub const PRUNE_WINDOW_HEIGHTS: u64 = 50_000;

/// Saturating pending-map cutoff observed at `0x2760048` (live) and `0x5afa04e` (slow) (`0x3e8`).
pub const PENDING_CUTOFF_WINDOW: u64 = 1_000;

/// Exact `qrs` (`tracker + 0x48`) element stride observed at `0x27600f0` (`0x68` = 104 bytes).
pub const QRS_ENTRY_SIZE_BYTES: usize = 0x68;

/// Exact 6-field serialization wire order proven in `0x275ef30..0x275f127` (`.rodata 0x5f6b28`).
pub const HASH_SIGNATURE_TRACKER_WIRE_FIELDS: [&str; 6] = [
    "tracker",
    "qrs",
    "highest_quorum_height",
    "htm",
    "adu",
    "h",
];

/// Binary-proven 2-variant `QuorumStatus` wire encoding (`0x28a05e0..0x28a0856`, `.rodata 0x5ff063`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuorumStatus {
    /// Unit variant `"N"` (`0x5ff063`).
    NoQuorum,
    /// Payload variant `"Q"` (`0x5ff065`).
    Quorum(Digest),
}

impl QuorumStatus {
    pub const fn wire_tag(self) -> &'static str {
        match self {
            Self::NoQuorum => "N",
            Self::Quorum(_) => "Q",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordVoteResult {
    pub accepted_height_bound: bool,
    pub admissions: Vec<Admission>,
    pub selected_transition: bool,
    pub prune_cutoff: Option<u64>,
    pub sealed_now: bool,
}

/// Convert an `f64` delay in seconds (`[tracker + 0x88]`, `0x515218d..0x51521da`)
/// into nanoseconds saturated to `i64::MAX` (`0x7fff_ffff_ffff_ffff`).
pub fn delay_secs_to_nanos(delay_secs: f64) -> Option<u64> {
    if !delay_secs.is_finite() || delay_secs < 0.0 {
        return None;
    }
    let nanos_f = delay_secs * 1_000_000_000.0;
    let max_i64 = i64::MAX as u64;
    if nanos_f >= max_i64 as f64 {
        Some(max_i64)
    } else {
        Some(nanos_f as u64)
    }
}

/// Timer eligibility predicate observed at `0x515218d..0x51522cd`:
/// eligible iff `current_nanos >= inserted_nanos + delay_nanos`.
pub fn timer_is_mature(inserted_nanos: u64, delay_secs: f64, current_nanos: u64) -> bool {
    let Some(delay_nanos) = delay_secs_to_nanos(delay_secs) else {
        return false;
    };
    current_nanos >= inserted_nanos.saturating_add(delay_nanos)
}

/// Complete offline logical model of `HashSignatureTracker` (`S + 0x3e50`).
#[derive(Clone, Debug, Default)]
pub struct HashSignatureTracker {
    pub snapshot: AdmissionSnapshot,
    pub handoff: TrackerProjection,
    /// `tracker + 0x60`: heights scheduled for timer-gated drain.
    pub pending_heights: BTreeSet<u64>,
    /// `tracker + 0x80`: unsigned running maximum height observed across transitions.
    pub max_watermark: u64,
    /// `tracker + 0x90`: seal marker set when a transitioning height equals `seal_target`.
    pub seal_marker: bool,
}

impl HashSignatureTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an admitted external `0xdd` vote, update watermark/seal/pruning on a
    /// false->true selection transition, and mirror state into `TrackerProjection`.
    pub fn record_vote(
        &mut self,
        vote: &ExternalDigestVote,
        support: &SupportContext,
        seal_target: Option<u64>,
    ) -> Option<RecordVoteResult> {
        if vote.action_tag != ACTION_TAG_ABCI_DIGEST_VOTE {
            return None;
        }
        if vote.height >= VOTE_HEIGHT_EXCLUSIVE_LIMIT {
            return Some(RecordVoteResult {
                accepted_height_bound: false,
                admissions: Vec::new(),
                selected_transition: false,
                prune_cutoff: None,
                sealed_now: false,
            });
        }

        let mut admissions = Vec::new();
        let mut transitioned = false;
        let ordered_keys: [Option<(Voter, bool)>; 2] = [
            vote.voter_32.map(|(k, e)| (Voter::Key32(k), e)),
            vote.voter_20.map(|(k, e)| (Voter::Key20(k), e)),
        ];

        for (voter, eligible) in ordered_keys.into_iter().flatten() {
            let decision = admission_for(&self.snapshot, vote.height, vote.digest, voter, eligible);
            admissions.push(decision);
            if !matches!(
                decision,
                Admission::ExistingCandidate | Admission::AdmitNew { .. }
            ) {
                continue;
            }
            let entry = self.snapshot.entry(vote.height).or_default();
            let cand = entry.candidates.entry(vote.digest).or_default();
            let before = if entry.selected.is_some() {
                true
            } else {
                supports(
                    &support.weights_32,
                    &cand.keys32,
                    support.fraction_20,
                    &support.eligible_20,
                    support.stored_total_20,
                    &cand.keys20,
                )
            };
            match voter {
                Voter::Key32(k) => {
                    cand.keys32.insert(k);
                }
                Voter::Key20(k) => {
                    cand.keys20.insert(k);
                }
            }
            if !before {
                let after = supports(
                    &support.weights_32,
                    &cand.keys32,
                    support.fraction_20,
                    &support.eligible_20,
                    support.stored_total_20,
                    &cand.keys20,
                );
                if after {
                    entry.selected = Some(vote.digest);
                    transitioned = true;
                }
            }
            let handoff_entry = self.handoff.heights.entry(vote.height).or_default();
            handoff_entry.selected = entry.selected;
            let ids: BTreeSet<MemberId> = cand.keys32.clone();
            handoff_entry.candidates.insert(vote.digest, ids);
        }

        let mut prune_cutoff = None;
        let mut sealed_now = false;
        if transitioned {
            // `0x27605e4` / `0x5afb227`: unsigned running maximum watermark
            if vote.height > self.max_watermark {
                self.max_watermark = vote.height;
            }
            // `0x5afb262 -> 0x4dbe1e0`: schedule height in `tracker + 0x60`
            self.pending_heights.insert(vote.height);
            // `0x2760627` / `0x5afb26f`: seal marker when h == seal_target
            if seal_target == Some(vote.height) {
                self.seal_marker = true;
                sealed_now = true;
            }
            // `0x276063a` / `0x5afb284`: saturating cutoff = h.saturating_sub(50_000)
            let cutoff = vote.height.saturating_sub(PRUNE_WINDOW_HEIGHTS);
            prune_cutoff = Some(cutoff);
            self.prune_below(cutoff);
        }

        Some(RecordVoteResult {
            accepted_height_bound: true,
            admissions,
            selected_transition: transitioned,
            prune_cutoff,
            sealed_now,
        })
    }

    /// Re-evaluate pending unselected candidates after a staking/validator update
    /// (`0x54cae80 -> 0x5afa3b0 -> 0x5373e40`). Returns heights that newly transitioned.
    pub fn recheck_candidates(&mut self, support: &SupportContext) -> Vec<u64> {
        let mut newly_selected = Vec::new();
        for (&height, entry) in &mut self.snapshot {
            if entry.selected.is_some() {
                continue;
            }
            let winner = entry
                .candidates
                .iter()
                .find(|(_, cand)| {
                    supports(
                        &support.weights_32,
                        &cand.keys32,
                        support.fraction_20,
                        &support.eligible_20,
                        support.stored_total_20,
                        &cand.keys20,
                    )
                })
                .map(|(&digest, _)| digest);
            if let Some(digest) = winner {
                entry.selected = Some(digest);
                self.handoff.heights.entry(height).or_default().selected = Some(digest);
                self.pending_heights.insert(height);
                if height > self.max_watermark {
                    self.max_watermark = height;
                }
                newly_selected.push(height);
            }
        }
        for &h in &newly_selected {
            self.prune_below(h.saturating_sub(PRUNE_WINDOW_HEIGHTS));
        }
        newly_selected
    }

    /// Prune tracker height entries strictly below `cutoff`.
    pub fn prune_below(&mut self, cutoff: u64) {
        self.snapshot.retain(|&h, _| h >= cutoff);
        self.handoff.heights.retain(|&h, _| h >= cutoff);
        self.pending_heights.retain(|&h| h >= cutoff);
    }

    /// Drain timer-eligible heights (`0x5afa030`), returning both the drained rows
    /// and their serialized `abci_digest_quorum` JSON sink lines (`node115-quorum-line`).
    pub fn drain_eligible(
        &mut self,
        timer_eligible_heights: &[u64],
        registry: &Registry,
        registry_context: u64,
    ) -> (Vec<ReferenceRow>, Vec<String>) {
        for &h in timer_eligible_heights {
            if self.pending_heights.remove(&h) {
                self.handoff.extract_selected(h, registry, registry_context);
            }
        }
        let rows = self.handoff.drain_ready();
        let quorum_lines = rows.iter().map(quorum_log_line).collect();
        (rows, quorum_lines)
    }

    pub fn selected_digest(&self, height: u64) -> Option<Digest> {
        self.snapshot.get(&height)?.selected
    }

    pub fn quorum_status(&self, height: u64) -> QuorumStatus {
        match self.selected_digest(height) {
            Some(digest) => QuorumStatus::Quorum(digest),
            None => QuorumStatus::NoQuorum,
        }
    }

    /// Prune pending timer heights below `current_height.saturating_sub(PENDING_CUTOFF_WINDOW)`
    /// matching live `0x2760048` and slow `0x5afa04e` (`sub rax, 0x3e8; cmovae`).
    pub fn prune_pending_window(&mut self, current_height: u64) -> u64 {
        let cutoff = current_height.saturating_sub(PENDING_CUTOFF_WINDOW);
        self.pending_heights.retain(|&h| h >= cutoff);
        cutoff
    }

    pub fn retained_heights(&self) -> BTreeMap<u64, Option<Digest>> {
        self.snapshot
            .iter()
            .map(|(&h, e)| (h, e.selected))
            .collect()
    }
}
