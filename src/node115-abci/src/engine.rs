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
use crate::state::AbciState;

/// Exact retention count passed to `prune_lowest_evm_checkpoints` at `0x4d98d51` (`mov esi, 0x64`).
pub const PRUNE_KEEP_EVM_CHECKPOINTS: usize = 100;

/// Completion sentinel checked/written by `tar_evm_checkpoints` (`0x38c40f0`, rodata `0x7a1497`).
pub const TAR_COMPLETE_MARKER: &str = "TAR_COMPLETE";

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
}

/// Select the lowest checkpoint heights to prune while retaining the newest `keep`
/// checkpoints (native `0x4d98d51` passes `keep = PRUNE_KEEP_EVM_CHECKPOINTS = 100`).
pub fn select_checkpoints_to_prune(mut heights: Vec<u64>, keep: usize) -> Vec<u64> {
    heights.sort_unstable();
    heights.dedup();
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
