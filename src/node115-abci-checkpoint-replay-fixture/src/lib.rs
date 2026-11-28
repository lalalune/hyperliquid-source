//! Bounded offline node #115 fixture connecting:
//! 1. Checkpoint discovery & restore-to-first-replay key (`qcp-first-replay-key`)
//! 2. Root digest selector (`0x160bee0`) & fallback `.bss` cell writer (`0x5cadd50` -> `0x6500098`)
//!    (`qcp-root-selector`, `qcp-root-cell-writer`)
//! 3. Same-owner `0x5a04e40` replay execution (`H -> H + 1` at `0x54838d3..0x54838e5`),
//!    external `0xdd` vote ingestion (`S + 0x3e50`), two-gate support transition,
//!    timer-eligible drain (`0x5afa030`), sink-before-comparison (`ctx + 0x280` -> `ctx + 0x400`),
//!    and post-comparison local root history write (`0x5a07ec0 -> 0x5a03fa0`)
//!    (`qcp-expected-root-provenance`).
//!
//! All data is synthetic and offline. Cryptographic signature recovery (`0x64e0ad8`),
//! timer-delay configuration (`tracker + 0x88`), CPUID feature semantics, and live-chain
//! trust authority remain explicit unresolved boundaries.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use node115_checkpoint_discovery::find_checkpoint;
use node115_digest_reference_handoff::{
    Address, Digest, MemberId, Registry, ReplayHandoff, TrackerProjection, replay_handoff,
};
use node115_digest_support_gate::{Key20, Key32, supports};
use node115_digest_vote_admission::{
    Admission, Snapshot as AdmissionSnapshot, Voter, admission_for,
};

/// Upper bound on ABCI digest-vote height checked in `0x58694f9..0x5869506` (`>=` rejects with 0x154).
pub const VOTE_HEIGHT_EXCLUSIVE_LIMIT: u64 = 0x0ccc_cccc_cccc_cccc;

/// Action tag for ABCI digest votes in slow-engine router `0x54a3a00` (jump table `0x92688c[87]`).
pub const ACTION_TAG_ABCI_DIGEST_VOTE: u64 = 0xdd;

/// Root-cadence divisor verified at `0x5a07ee2..0x5a07f01` (`height % 10_000 == 0`).
pub const DEFAULT_ROOT_CADENCE_MODULUS: u64 = 10_000;

/// Restored checkpoint fields traced by `qcp-first-replay-key` (`0x3c128ca`, `0x2cb7976..0x2cb80c6`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestoredState {
    pub checkpoint_path: PathBuf,
    /// `[S + 0x28]`: persisted checkpoint height `H`, verified against requested height.
    pub height: u64,
    /// `[S + 0x30]`: persisted round `R`.
    pub round: u64,
    /// `[S + 0x18]`: incremented with saturation on accepted loader lane (`0x3c128ca`).
    pub loader_seq: u64,
    /// `[S + 0x20]`: copied from `[S + 0x30]` on accepted loader lane.
    pub copied_round: u64,
    /// Initial replay key copied into parent `+0x9a0`/`+0x9a8` with no arithmetic.
    pub replay_initializer: ReplayInitializer,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplayInitializer {
    /// Low qword copied from `[S + 0x28]`.
    pub initial_height: u64,
    /// High qword copied from `[S + 0x30]`.
    pub initial_round: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RestoreError {
    CheckpointNotFound { requested_height: u64 },
    HeightMismatch { requested: u64, persisted: u64 },
}

/// Discover a checkpoint directory via `node115-checkpoint-discovery` and apply the
/// observed `qcp-first-replay-key` restore field contract.
pub fn restore_checkpoint(
    checkpoints_dir: &Path,
    requested_height: u64,
    persisted_height: u64,
    persisted_round: u64,
    persisted_seq: u64,
) -> Result<RestoredState, RestoreError> {
    let candidate = find_checkpoint(checkpoints_dir, requested_height)
        .ok_or(RestoreError::CheckpointNotFound { requested_height })?;
    if persisted_height != requested_height {
        return Err(RestoreError::HeightMismatch {
            requested: requested_height,
            persisted: persisted_height,
        });
    }
    Ok(RestoredState {
        checkpoint_path: candidate.path,
        height: persisted_height,
        round: persisted_round,
        loader_seq: persisted_seq.saturating_add(1),
        copied_round: persisted_round,
        replay_initializer: ReplayInitializer {
            initial_height: persisted_height,
            initial_round: persisted_round,
        },
    })
}

/// Model of the 3-qword `.bss` cell at `0x6500098` (`qcp-root-cell-writer`, `0x5cadd50`).
/// Symbolic CPUID meanings and concurrent memory ordering are explicitly omitted.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RootSelectorCell {
    /// Qwords at `0x6500098 + {0, 8, 16}`.
    pub words: [u64; 3],
}

impl RootSelectorCell {
    /// Models the selected `0x5cadd50` return block (`0x5cae3a1..`):
    /// writes `words[0] = r13 | rdi`, plus two derived words at `+8` and `+16`,
    /// while returning `r13` (not necessarily identical to `words[0]`).
    pub fn write_fallback(&mut self, r13: u64, rdi: u64, rdx: u64) -> u64 {
        self.words[0] = r13 | rdi;
        self.words[1] = rdx | r13;
        self.words[2] = rdx | rdi;
        r13
    }
}

/// Trace of the exact 4-stage `0x160bee0` selector evaluation (`qcp-root-selector`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectorTrace {
    pub effective_reads: Vec<u64>,
    pub fallback_invocations: usize,
    pub selector_byte: u8,
}

/// Exact repeated-read model of `0x160bee0` (`qcp-root-selector`).
/// Each stage reloads `cell.words[0]`; iff zero, calls `fallback(&mut cell)`.
/// Passing a custom `read_hook` allows testing non-stable cells between reads.
pub fn select_root_impl<F, R>(
    cell: &mut RootSelectorCell,
    mut read_word0: R,
    mut fallback: F,
) -> SelectorTrace
where
    R: FnMut(&RootSelectorCell, usize) -> u64,
    F: FnMut(&mut RootSelectorCell, usize) -> u64,
{
    let mut reads = Vec::with_capacity(4);
    let mut fallbacks = 0usize;
    let mut stage = 0usize;

    let mut next_word = |cell: &mut RootSelectorCell| -> u64 {
        let s = stage;
        stage += 1;
        let observed = read_word0(cell, s);
        let effective = if observed == 0 {
            fallbacks += 1;
            fallback(cell, s)
        } else {
            observed
        };
        reads.push(effective);
        effective
    };

    let w0 = next_word(cell);
    if (w0 & (1u64 << 19)) != 0 {
        let w1 = next_word(cell);
        if (w1 & (1u64 << 25)) != 0 {
            return SelectorTrace {
                effective_reads: reads,
                fallback_invocations: fallbacks,
                selector_byte: 4,
            };
        }
    }
    let w2 = next_word(cell);
    if (w2 & (1u64 << 15)) != 0 {
        return SelectorTrace {
            effective_reads: reads,
            fallback_invocations: fallbacks,
            selector_byte: 3,
        };
    }
    let w3 = next_word(cell);
    let selector_byte = 1 + (((w3 >> 10) & 1) as u8);
    SelectorTrace {
        effective_reads: reads,
        fallback_invocations: fallbacks,
        selector_byte,
    }
}

/// Explicit provenance tag preventing conflation of locally produced state roots
/// (`ctx + 0x400`) with externally supplied expected roots (`S + 0x3e50`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RootProvenance {
    /// Produced locally AFTER replay comparison by `0x5a07ec0 -> 0x548dad0 -> 0x5a03fa0`.
    LocalPostComparison {
        height: u64,
        selector_byte: u8,
        digest: Digest,
    },
    /// Supplied externally via action tag `0xdd` into `S + 0x3e50`, selected via the
    /// two-gate false-to-true edge, and drained via `0x54897e0 -> 0x5afa030`.
    ExternalDigestVoteQuorum {
        action_tag: u64,
        height: u64,
        digest: Digest,
        resolved_members: BTreeSet<Address>,
    },
}

/// Synthetic external `0xdd` ABCI digest vote input after upstream signature recovery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExternalDigestVote {
    pub action_tag: u64,
    pub height: u64,
    pub digest: Digest,
    /// Optional 32-byte key family voter and caller-supplied eligibility result.
    pub voter_32: Option<(Key32, bool)>,
    /// Optional 20-byte key family voter and caller-supplied eligibility result.
    pub voter_20: Option<(Key20, bool)>,
}

/// Support-gate context supplied to `0x5373810` (`node115-digest-support-gate`).
#[derive(Clone, Debug)]
pub struct SupportContext {
    pub weights_32: BTreeMap<Key32, u64>,
    pub fraction_20: f64,
    pub eligible_20: BTreeSet<Key20>,
    pub stored_total_20: u64,
}

/// Replay block input for `0x5a04e40`.
#[derive(Clone, Debug)]
pub struct ReplayBlock {
    pub prev_round: u64,
    pub new_round: u64,
    pub expected_loader_seq: u64,
    pub expected_copied_round: u64,
    pub votes: Vec<ExternalDigestVote>,
    /// Caller-supplied heights whose pending timer in `tracker + 0x60` has matured.
    /// Timer delay arithmetic (`tracker + 0x88`) remains an explicit external input.
    pub timer_eligible_heights: Vec<u64>,
    /// Synthetic locally produced state root for the block's post-increment height (`H + 1`),
    /// stored into `ctx + 0x400` ONLY after comparison when cadence triggers.
    pub synthetic_local_root: Option<Digest>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BlockAdmissionError {
    NonAdvancingRound { prev_round: u64, new_round: u64 },
    PrevRoundMismatch { state_round: u64, block_prev_round: u64 },
    LoaderSeqMismatch { state_seq: u64, block_seq: u64 },
    CopiedRoundMismatch { state_copied: u64, block_copied: u64 },
    InvalidActionTag { tag: u64 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VoteStepOutcome {
    HeightAtOrAboveLimit { height: u64 },
    Processed {
        admissions: Vec<Admission>,
        selected_transition: bool,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockExecutionReport {
    pub post_height: u64,
    pub post_round: u64,
    pub vote_outcomes: Vec<VoteStepOutcome>,
    pub drained_provenance: Vec<RootProvenance>,
    pub handoff: ReplayHandoff,
    pub local_root_recorded: Option<(RootProvenance, SelectorTrace)>,
}

/// Single-owner replay engine fixture matching `0x5a04e40` (`ctx` owning both
/// `state` at `ctx + 0x450` with tracker `S + 0x3e50` and local history at `ctx + 0x400`).
#[derive(Clone, Debug)]
pub struct ReplayEngineFixture {
    pub state: RestoredState,
    /// `S + 0x3e50` candidate/selector snapshot (admission & support gate state).
    pub tracker_snapshot: AdmissionSnapshot,
    /// `S + 0x3e50` projection for `0x5377df0 -> 0x51520f0 -> 0x5afa030` handoff.
    pub tracker_handoff: TrackerProjection,
    /// `S + 0x3e50 + 0x60` pending heights scheduled by `0x4dbe1e0`.
    pub pending_timer_heights: BTreeSet<u64>,
    /// `ctx + 0x400` local raw-root history (strictly local provenance).
    pub local_raw_history: BTreeMap<u64, Digest>,
    /// `[S + 0x39c8]` periodic root cadence modulus (0 disables periodic non-10k trigger).
    pub periodic_cadence: u64,
    /// Optional `[S + 0x10f0]` hardfork height trigger.
    pub hardfork_height: Option<u64>,
    /// `.bss` root-selector cell at `0x6500098`.
    pub selector_cell: RootSelectorCell,
}

impl ReplayEngineFixture {
    pub fn from_restored(
        state: RestoredState,
        periodic_cadence: u64,
        hardfork_height: Option<u64>,
    ) -> Self {
        Self {
            state,
            tracker_snapshot: BTreeMap::new(),
            tracker_handoff: TrackerProjection::default(),
            pending_timer_heights: BTreeSet::new(),
            local_raw_history: BTreeMap::new(),
            periodic_cadence,
            hardfork_height,
            selector_cell: RootSelectorCell::default(),
        }
    }

    fn root_cadence_matches(&self, height: u64) -> bool {
        if height.is_multiple_of(DEFAULT_ROOT_CADENCE_MODULUS) {
            return true;
        }
        if self.hardfork_height == Some(height) {
            return true;
        }
        self.periodic_cadence > 0 && height.is_multiple_of(self.periodic_cadence)
    }

    fn ingest_vote(
        &mut self,
        vote: &ExternalDigestVote,
        support: &SupportContext,
    ) -> Result<VoteStepOutcome, BlockAdmissionError> {
        if vote.action_tag != ACTION_TAG_ABCI_DIGEST_VOTE {
            return Err(BlockAdmissionError::InvalidActionTag {
                tag: vote.action_tag,
            });
        }
        if vote.height >= VOTE_HEIGHT_EXCLUSIVE_LIMIT {
            return Ok(VoteStepOutcome::HeightAtOrAboveLimit {
                height: vote.height,
            });
        }

        let mut admissions = Vec::new();
        let mut transitioned = false;

        // Native order (`0x28b2f50..`, `0x537aa60`): 32-byte key family before 20-byte key family.
        // Second family is evaluated against the state AFTER the first family's insertion.
        let ordered_keys: [Option<(Voter, bool)>; 2] = [
            vote.voter_32.map(|(k, e)| (Voter::Key32(k), e)),
            vote.voter_20.map(|(k, e)| (Voter::Key20(k), e)),
        ];

        for item in ordered_keys.into_iter().flatten() {
            let (voter, eligible) = item;
            let decision = admission_for(
                &self.tracker_snapshot,
                vote.height,
                vote.digest,
                voter,
                eligible,
            );
            admissions.push(decision);
            if !matches!(
                decision,
                Admission::ExistingCandidate | Admission::AdmitNew { .. }
            ) {
                continue;
            }

            let entry = self.tracker_snapshot.entry(vote.height).or_default();
            let candidate = entry.candidates.entry(vote.digest).or_default();

            let already_selected_or_supported = if entry.selected.is_some() {
                true
            } else {
                supports(
                    &support.weights_32,
                    &candidate.keys32,
                    support.fraction_20,
                    &support.eligible_20,
                    support.stored_total_20,
                    &candidate.keys20,
                )
            };

            match voter {
                Voter::Key32(k) => {
                    candidate.keys32.insert(k);
                }
                Voter::Key20(k) => {
                    candidate.keys20.insert(k);
                }
            }

            if !already_selected_or_supported {
                let after = supports(
                    &support.weights_32,
                    &candidate.keys32,
                    support.fraction_20,
                    &support.eligible_20,
                    support.stored_total_20,
                    &candidate.keys20,
                );
                if after {
                    // False -> true transition latches selector +0x20 := 0 and digest +0x21 := D.
                    entry.selected = Some(vote.digest);
                    transitioned = true;
                    // `0x5afb262 -> 0x4dbe1e0` schedules height into `tracker + 0x60`.
                    self.pending_timer_heights.insert(vote.height);
                }
            }

            // Mirror logical state into `TrackerProjection` (preserving the 32-byte first collection).
            let handoff_entry = self.tracker_handoff.heights.entry(vote.height).or_default();
            handoff_entry.selected = entry.selected;
            let member_ids: BTreeSet<MemberId> = candidate.keys32.clone();
            handoff_entry.candidates.insert(vote.digest, member_ids);
        }

        Ok(VoteStepOutcome::Processed {
            admissions,
            selected_transition: transitioned,
        })
    }

    /// Execute one block following the observed `0x5a04e40` ordering:
    /// 1. Block header admission (`0x5a04eea..0x5a04f23`)
    /// 2. `H -> H + 1` saturating height advance + round store (`0x54838d3..0x54838f1`)
    /// 3. External `0xdd` votes into `S + 0x3e50` (`0x5869400 -> 0x5afadd0 -> 0x537aa60`)
    /// 4. Finalizer drain (`0x54897e0 -> 0x5afa030`) over caller-supplied timer-eligible heights
    /// 5. Sink-before-comparison (`0x5a05c14..0x5a05e3c`) against `ctx + 0x400`
    /// 6. Post-comparison local root production (`0x5a05fc9 -> 0x5a07ec0 -> 0x5a03fa0`)
    pub fn apply_block<F>(
        &mut self,
        block: &ReplayBlock,
        support: &SupportContext,
        registry: &Registry,
        registry_context: u64,
        fallback_cpuid: F,
    ) -> Result<BlockExecutionReport, BlockAdmissionError>
    where
        F: FnMut(&mut RootSelectorCell, usize) -> u64,
    {
        self.apply_block_with_history_pruning(
            block,
            support,
            registry,
            registry_context,
            None,
            fallback_cpuid,
        )
    }

    /// Run the fixture with the selected local history pruning branch.
    /// `history_prune_base` is the caller-supplied context word at `ctx + 0x18`
    /// when pruning is enabled. `None` models the disabled flag at `ctx + 0x10`.
    pub fn apply_block_with_history_pruning<F>(
        &mut self,
        block: &ReplayBlock,
        support: &SupportContext,
        registry: &Registry,
        registry_context: u64,
        history_prune_base: Option<u64>,
        fallback_cpuid: F,
    ) -> Result<BlockExecutionReport, BlockAdmissionError>
    where
        F: FnMut(&mut RootSelectorCell, usize) -> u64,
    {
        // Step 1: Pre-execution header checks (`0x5a04eea..0x5a04f23`).
        if block.new_round <= block.prev_round {
            return Err(BlockAdmissionError::NonAdvancingRound {
                prev_round: block.prev_round,
                new_round: block.new_round,
            });
        }
        if self.state.round != block.prev_round {
            return Err(BlockAdmissionError::PrevRoundMismatch {
                state_round: self.state.round,
                block_prev_round: block.prev_round,
            });
        }
        if self.state.loader_seq != block.expected_loader_seq {
            return Err(BlockAdmissionError::LoaderSeqMismatch {
                state_seq: self.state.loader_seq,
                block_seq: block.expected_loader_seq,
            });
        }
        if self.state.copied_round != block.expected_copied_round {
            return Err(BlockAdmissionError::CopiedRoundMismatch {
                state_copied: self.state.copied_round,
                block_copied: block.expected_copied_round,
            });
        }

        // Step 2: Saturating height advance `H -> H + 1` and round update (`0x54838d3..0x54838f1`).
        self.state.height = self.state.height.saturating_add(1);
        self.state.round = block.new_round;

        // Step 3: Action execution (`0x5483e87 -> ... -> 0x5869400 -> 0x5afadd0 -> 0x537aa60`).
        let mut vote_outcomes = Vec::with_capacity(block.votes.len());
        for vote in &block.votes {
            vote_outcomes.push(self.ingest_vote(vote, support)?);
        }

        // Step 4: Finalizer drain (`0x54897e0 -> 0x5afa030 -> 0x4de0540 -> 0x51520f0`).
        for &height in &block.timer_eligible_heights {
            if self.pending_timer_heights.remove(&height) {
                self.tracker_handoff
                    .extract_selected(height, registry, registry_context);
            }
        }
        let drained_rows = self.tracker_handoff.drain_ready();
        let drained_provenance: Vec<RootProvenance> = drained_rows
            .iter()
            .map(|row| RootProvenance::ExternalDigestVoteQuorum {
                action_tag: ACTION_TAG_ABCI_DIGEST_VOTE,
                height: row.height,
                digest: row.digest,
                resolved_members: row.members.clone(),
            })
            .collect();

        // Step 5: Sink-before-comparison (`0x5a05c14..0x5a05e3c`) BEFORE `0x5a07ec0`.
        let handoff = replay_handoff(&drained_rows, &self.local_raw_history);

        // The selected branch removes old local entries after this block's comparison
        // and before the end selector can insert the next root.
        if let Some(base) = history_prune_base {
            self.local_raw_history = self.local_raw_history.split_off(&base.saturating_add(1));
        }

        // Step 6: Post-comparison local root production (`0x5a05fc9 -> 0x5a07ec0 -> 0x5a03fa0`).
        let post_height = self.state.height;
        let local_root_recorded = if self.root_cadence_matches(post_height) {
            if let Some(local_digest) = block.synthetic_local_root {
                let trace = select_root_impl(
                    &mut self.selector_cell,
                    |cell, _| cell.words[0],
                    fallback_cpuid,
                );
                self.local_raw_history.insert(post_height, local_digest);
                Some((
                    RootProvenance::LocalPostComparison {
                        height: post_height,
                        selector_byte: trace.selector_byte,
                        digest: local_digest,
                    },
                    trace,
                ))
            } else {
                None
            }
        } else {
            None
        };

        Ok(BlockExecutionReport {
            post_height,
            post_round: self.state.round,
            vote_outcomes,
            drained_provenance,
            handoff,
            local_root_recorded,
        })
    }
}
