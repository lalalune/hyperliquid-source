//! Node #115 `l1/src/abci/engine.rs` block-execution, root-cadence, quorum-sink,
//! and EVM checkpoint maintenance engine.
//!
//! Binary anchors (`RE-009-node115-abci-crate-map`, `RE-009-node115-expected-root-provenance`):
//! - `0x5a04e40..0x5a065f8` (`engine.rs:168..175, 262, 431`): single-owner apply_block
//! - `0x5a07ec0..0x5a0871c` (`engine.rs:316:46`): end_root_selector (`% 10_000 == 0` / hardfork / `% cadence`)
//! - `0x4d98c40..0x4d98f80` (`engine.rs:332, 339`): `tar_evm_checkpoints` vs `prune_lowest_evm_checkpoints(100)`
//! - `0x38c40f0..0x38c51ee` (`engine.rs:514`): daily EVM checkpoint tar (`TAR_COMPLETE`, `tar -C <dir> -cf <out> <name>`)

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use node115_abci_checkpoint_replay_fixture::{
    BlockAdmissionError, DEFAULT_ROOT_CADENCE_MODULUS, ExternalDigestVote, RootProvenance,
    RootSelectorCell, SelectorTrace, SupportContext, select_root_impl,
};
use node115_digest_reference_handoff::{Digest, Registry, ReplayHandoff, replay_handoff};

use crate::hash_signature_tracker::{HashSignatureTracker, RecordVoteResult};
use crate::state::{AbciState, ApplyBlockPreconditionError};

/// Exact retention count passed to `prune_lowest_evm_checkpoints` at `0x4d98d51` (`mov esi, 0x64`).
pub const PRUNE_KEEP_EVM_CHECKPOINTS: usize = 100;

/// Completion sentinel checked/written by `tar_evm_checkpoints` (`0x38c40f0`, rodata `0x7a1497`).
pub const TAR_COMPLETE_MARKER: &str = "TAR_COMPLETE";

/// Per-checkpoint deletion sentinel checked by `0x3d5dca0` (`0x3d5dd85`, rodata `0x44c7fc`).
pub const MARKED_FOR_DELETION_MARKER: &str = "MARKED_FOR_DELETION";

/// Daily EVM checkpoint archive subdirectory observed at `0x38c4478` (rodata `0x438f1d`).
pub const DAILY_EVM_CHECKPOINTS_SUBDIR: &str = "data/daily_evm_checkpoints";

/// Block input for `AbciEngine::apply_block`.
#[derive(Clone, Debug)]
pub struct EngineBlock {
    pub prev_round: u64,
    pub new_round: u64,
    pub expected_loader_seq: u64,
    pub expected_copied_round: u64,
    pub external_votes: Vec<ExternalDigestVote>,
    pub timer_eligible_heights: Vec<u64>,
    pub synthetic_local_root: Option<Digest>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EngineBlockReport {
    pub height: u64,
    pub round: u64,
    pub vote_results: Vec<RecordVoteResult>,
    pub quorum_sink_lines: Vec<String>,
    pub handoff: ReplayHandoff,
    pub local_root: Option<(RootProvenance, SelectorTrace)>,
}

/// Cohesive offline ABCI engine uniting `AbciState`, `HashSignatureTracker` (`S + 0x3e50`),
/// quorum JSON sink (`ctx + 0x280`), local raw-root history (`ctx + 0x400`), and root selector cell (`0x6500098`).
#[derive(Clone, Debug)]
pub struct AbciEngine {
    pub state: AbciState,
    pub tracker: HashSignatureTracker,
    pub local_raw_history: BTreeMap<u64, Digest>,
    pub quorum_sink_log: Vec<String>,
    pub selector_cell: RootSelectorCell,
    pub seal_target: Option<u64>,
}

impl AbciEngine {
    pub fn new(state: AbciState) -> Self {
        Self {
            state,
            tracker: HashSignatureTracker::new(),
            local_raw_history: BTreeMap::new(),
            quorum_sink_log: Vec::new(),
            selector_cell: RootSelectorCell::default(),
            seal_target: None,
        }
    }

    pub fn root_cadence_matches(&self, height: u64) -> bool {
        if height.is_multiple_of(DEFAULT_ROOT_CADENCE_MODULUS) {
            return true;
        }
        if self.state.hardfork_height == Some(height) {
            return true;
        }
        self.state.periodic_root_cadence > 0
            && height.is_multiple_of(self.state.periodic_root_cadence)
    }

    pub fn apply_block<F>(
        &mut self,
        block: &EngineBlock,
        support: &SupportContext,
        registry: &Registry,
        registry_context: u64,
        fallback_cpuid: F,
    ) -> Result<EngineBlockReport, BlockAdmissionError>
    where
        F: FnMut(&mut RootSelectorCell, usize) -> u64,
    {
        if block.new_round <= block.prev_round {
            return Err(BlockAdmissionError::NonAdvancingRound {
                prev_round: block.prev_round,
                new_round: block.new_round,
            });
        }
        if self.state.round() != block.prev_round {
            return Err(BlockAdmissionError::PrevRoundMismatch {
                state_round: self.state.round(),
                block_prev_round: block.prev_round,
            });
        }
        if self.state.inner.loader_seq != block.expected_loader_seq {
            return Err(BlockAdmissionError::LoaderSeqMismatch {
                state_seq: self.state.inner.loader_seq,
                block_seq: block.expected_loader_seq,
            });
        }
        if self.state.inner.copied_round != block.expected_copied_round {
            return Err(BlockAdmissionError::CopiedRoundMismatch {
                state_copied: self.state.inner.copied_round,
                block_copied: block.expected_copied_round,
            });
        }

        // 1. Advance height H -> H+1 and round (`0x54838d3..0x54838f1`)
        self.state.advance_block(block.new_round);

        // 2. Process external 0xdd votes into S + 0x3e50
        let mut vote_results = Vec::with_capacity(block.external_votes.len());
        for vote in &block.external_votes {
            let res = self
                .tracker
                .record_vote(vote, support, self.seal_target)
                .ok_or(BlockAdmissionError::InvalidActionTag {
                    tag: vote.action_tag,
                })?;
            vote_results.push(res);
        }

        // 3. Finalizer drain (`0x54897e0 -> 0x5afa030`) + quorum sink lines (`ctx + 0x280`)
        let (rows, quorum_sink_lines) = self.tracker.drain_eligible(
            &block.timer_eligible_heights,
            registry,
            registry_context,
        );
        self.quorum_sink_log.extend(quorum_sink_lines.iter().cloned());

        // 4. Sink-before-comparison (`0x5a05c14..0x5a05e3c`) BEFORE `0x5a07ec0`
        let handoff = replay_handoff(&rows, &self.local_raw_history);

        // 5. Post-comparison local root production (`0x5a05fc9 -> 0x5a07ec0 -> 0x5a03fa0`)
        let post_height = self.state.height();
        let local_root = if self.root_cadence_matches(post_height) {
            if let Some(digest) = block.synthetic_local_root {
                let trace = select_root_impl(
                    &mut self.selector_cell,
                    |cell, _| cell.words[0],
                    fallback_cpuid,
                );
                self.local_raw_history.insert(post_height, digest);
                Some((
                    RootProvenance::LocalPostComparison {
                        height: post_height,
                        selector_byte: trace.selector_byte,
                        digest,
                    },
                    trace,
                ))
            } else {
                None
            }
        } else {
            None
        };

        Ok(EngineBlockReport {
            height: post_height,
            round: self.state.round(),
            vote_results,
            quorum_sink_lines,
            handoff,
            local_root,
        })
    }

    /// Prune `local_raw_history` (`ctx + 0x400`) via `BTreeMap::split_off(&watermark.saturating_add(1))`
    /// matching `0x5a05ea1..0x5a05fbd` (`0x4de5ad0`) before `end_root_selector` (`0x5a07ec0`).
    /// Returns the number of entries evicted.
    pub fn prune_local_history_through(&mut self, verified_watermark: u64) -> usize {
        let cutoff = verified_watermark.saturating_add(1);
        let before = self.local_raw_history.len();
        let survivors = self.local_raw_history.split_off(&cutoff);
        let evicted = before - survivors.len();
        self.local_raw_history = survivors;
        evicted
    }

    /// Execute the full 7-stage `AbciEngine::apply_block` (`0x5a04e40..0x5a065f8`) pipeline
    /// in exact binary chronological order:
    /// 1. `PreGuards` (`0x5a04ec3..0x5a04f59`)
    /// 2. `BeginBlock` (`0x5a04fe9 -> 0x5483850`)
    /// 3. `ExecuteActions` (`0x5a05050..0x5a055b0`)
    /// 4. `EndBlock` (`0x5a055b0 -> 0x54897e0`)
    /// 5. `UpdateDigestQuorum` (`0x5a0584e -> 0x4de4a60`)
    /// 6. `VerifyStateRoot` (`0x5a05c5e -> 0x4e3a020`)
    /// 7. `PruneHistory` (`0x5a05ea1..0x5a05fbd -> 0x4de5ad0`)
    #[allow(clippy::too_many_arguments)]
    pub fn apply_block_pipeline<FBegin, FAction, FEnd, FCpuid>(
        &mut self,
        input: &ApplyBlockPipelineInput<'_>,
        support: &SupportContext,
        registry: &Registry,
        registry_context: u64,
        mut on_begin_block: FBegin,
        mut on_action: FAction,
        mut on_end_block: FEnd,
        fallback_cpuid: FCpuid,
    ) -> Result<ApplyBlockPipelineReport, ApplyBlockPipelineError>
    where
        FBegin: FnMut(u64),
        FAction: FnMut(usize),
        FEnd: FnMut(u64),
        FCpuid: FnMut(&mut RootSelectorCell, usize) -> u64,
    {
        let mut stages = Vec::with_capacity(7);

        // Stage 1: 6 ordered pre-execution guards (`0x5a04ec3..0x5a04f59`)
        self.state
            .validate_apply_preconditions(
                input.block.prev_round,
                input.block.new_round,
                input.state_time,
                input.block_parent_time,
                input.header_actions,
                input.payload_actions,
                input.feature_version,
            )
            .map_err(ApplyBlockPipelineError::Precondition)?;
        stages.push(ApplyBlockStage::PreGuards);

        // Stage 2: Exchange::begin_block (`0x5a04fe9 -> 0x5483850`)
        let next_height = self.state.height().saturating_add(1);
        on_begin_block(next_height);
        stages.push(ApplyBlockStage::BeginBlock);

        // Stage 3: Action/bundle execution loop (`0x5a05050..0x5a055b0`)
        for idx in 0..(input.payload_actions as usize) {
            on_action(idx);
        }
        stages.push(ApplyBlockStage::ExecuteActions);

        // Stage 4: Exchange::end_block (`0x5a055b0 -> 0x54897e0`)
        on_end_block(next_height);
        stages.push(ApplyBlockStage::EndBlock);

        // Stages 5 & 6: Digest quorum update (`0x5a0584e -> 0x4de4a60`) + state-root verification (`0x5a05c5e -> 0x4e3a020`)
        let report = self
            .apply_block(
                input.block,
                support,
                registry,
                registry_context,
                fallback_cpuid,
            )
            .map_err(ApplyBlockPipelineError::Admission)?;
        stages.push(ApplyBlockStage::UpdateDigestQuorum);
        stages.push(ApplyBlockStage::VerifyStateRoot);

        // Stage 7: History cutoff prune (`0x5a05ea1..0x5a05fbd -> 0x4de5ad0`)
        let evicted = match input.prune_watermark {
            Some(wm) => self.prune_local_history_through(wm),
            None => 0,
        };
        stages.push(ApplyBlockStage::PruneHistory);

        Ok(ApplyBlockPipelineReport {
            stages,
            engine_report: report,
            pruned_history_entries: evicted,
        })
    }
}

/// Exact chronological execution stages observed in `AbciEngine::apply_block` (`0x5a04e40..0x5a065f8`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplyBlockStage {
    PreGuards,
    BeginBlock,
    ExecuteActions,
    EndBlock,
    UpdateDigestQuorum,
    VerifyStateRoot,
    PruneHistory,
}

/// Inputs for `AbciEngine::apply_block_pipeline`.
#[derive(Clone, Debug)]
pub struct ApplyBlockPipelineInput<'a> {
    pub block: &'a EngineBlock,
    pub state_time: (u64, u64),
    pub block_parent_time: (u64, u64),
    pub header_actions: u64,
    pub payload_actions: u64,
    pub feature_version: u8,
    pub prune_watermark: Option<u64>,
}

/// Error returned by `AbciEngine::apply_block_pipeline`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ApplyBlockPipelineError {
    Precondition(ApplyBlockPreconditionError),
    Admission(BlockAdmissionError),
}

/// Structured result returned by `AbciEngine::apply_block_pipeline`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplyBlockPipelineReport {
    pub stages: Vec<ApplyBlockStage>,
    pub engine_report: EngineBlockReport,
    pub pruned_history_entries: usize,
}

/// Select the lowest checkpoint rows by height while retaining the newest `keep` rows.
/// Equal heights still occupy distinct entries in the count. Returns the selected
/// heights in ascending order for the offline fixture.
pub fn select_checkpoints_to_prune(mut heights: Vec<u64>, keep: usize) -> Vec<u64> {
    heights.sort_unstable();
    if heights.len() <= keep {
        return Vec::new();
    }
    let drop_count = heights.len() - keep;
    heights.into_iter().take(drop_count).collect()
}

/// Build the offline daily EVM checkpoint archive `tar -C <parent> -cf <archive> <entry>`
/// command observed in `0x38c40f0` (`engine.rs:514`), returning `None` if `TAR_COMPLETE`
/// already exists alongside the archive.
pub fn build_daily_evm_tar_command(
    parent_dir: &Path,
    checkpoint_entry: &str,
    output_tar: &Path,
    tar_complete_dir: &Path,
) -> Option<Command> {
    if tar_complete_dir.join(TAR_COMPLETE_MARKER).is_file() {
        return None;
    }
    let mut cmd = Command::new("tar");
    cmd.arg("-C")
        .arg(parent_dir)
        .arg("-cf")
        .arg(output_tar)
        .arg(checkpoint_entry);
    Some(cmd)
}

/// Return the path of the `TAR_COMPLETE` marker for a daily archive directory.
pub fn tar_complete_marker_path(dir: &Path) -> PathBuf {
    dir.join(TAR_COMPLETE_MARKER)
}

/// Format the daily EVM checkpoint tar path observed at `0x38c4478` (`.rodata 0x438f1b`):
/// `{home_dir}/data/daily_evm_checkpoints/{date_dir}/{name}_{suffix}.tar`.
pub fn daily_evm_checkpoint_tar_path(
    home_dir: &Path,
    date_dir: &str,
    name: &str,
    suffix: &str,
) -> PathBuf {
    home_dir
        .join(DAILY_EVM_CHECKPOINTS_SUBDIR)
        .join(date_dir)
        .join(format!("{name}_{suffix}.tar"))
}

/// Classification of an EVM checkpoint directory by `0x3d5dca0` (`l1/src/abci/engine.rs:557`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvmCheckpointFilterOutcome {
    /// Directory contains `MARKED_FOR_DELETION`; skipped from active filter (`0x3d5ddaa`).
    SkippedMarkedForDeletion,
    /// Height `< min_expected`; flagged as `"straggler evm state checkpoint"` (`0x3d5ddf1..0x3d5de14`) and dropped.
    DroppedStraggler,
    /// Height satisfies `h < upper_exclusive && h >= min_expected && h <= max_inclusive` (`0x3d5de80..0x3d5de9b`).
    Retained,
    /// Height is outside `[min_expected, min(upper_exclusive - 1, max_inclusive)]` and dropped.
    DroppedOutOfWindow,
}

/// Evaluate the exact `0x3d5dca0` checkpoint filter predicate (`0x3d5dd85..0x3d5de9b`).
pub fn classify_evm_checkpoint_entry(
    checkpoint_dir: &Path,
    height: u64,
    min_expected: u64,
    upper_exclusive: u64,
    max_inclusive: u64,
) -> EvmCheckpointFilterOutcome {
    if checkpoint_dir.join(MARKED_FOR_DELETION_MARKER).exists() {
        return EvmCheckpointFilterOutcome::SkippedMarkedForDeletion;
    }
    if height < min_expected {
        return EvmCheckpointFilterOutcome::DroppedStraggler;
    }
    if height < upper_exclusive && height <= max_inclusive {
        EvmCheckpointFilterOutcome::Retained
    } else {
        EvmCheckpointFilterOutcome::DroppedOutOfWindow
    }
}
