#![no_std]
#![forbid(unsafe_code)]
//! Safe path-plan projection of the selected node115 checkpoint lifecycle.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckpointMode {
    Zero,
    Checkpoint,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CheckpointPlan {
    pub mode: CheckpointMode,
    pub source_copies: u8,
    pub copy_checkpoint: bool,
    pub process_lt_hashes: bool,
    pub publish: bool,
}

pub fn plan(
    nonzero_mode: bool,
    checkpoint_path_present: bool,
    lt_hashes_present: bool,
) -> CheckpointPlan {
    if !nonzero_mode {
        return CheckpointPlan {
            mode: CheckpointMode::Zero,
            source_copies: 1,
            copy_checkpoint: false,
            process_lt_hashes: false,
            publish: true,
        };
    }
    let checkpoint_copy = !checkpoint_path_present;
    CheckpointPlan {
        mode: CheckpointMode::Checkpoint,
        source_copies: 1 + u8::from(checkpoint_copy),
        copy_checkpoint: checkpoint_copy,
        process_lt_hashes: checkpoint_copy && lt_hashes_present,
        publish: true,
    }
}

#[cfg(test)]
mod tests {
    use super::{CheckpointMode, plan};

    #[test]
    fn zero_mode_takes_one_copy_and_skips_checkpoint_work() {
        let result = plan(false, false, true);
        assert_eq!(result.mode, CheckpointMode::Zero);
        assert_eq!(result.source_copies, 1);
        assert!(!result.copy_checkpoint);
        assert!(!result.process_lt_hashes);
        assert!(result.publish);
    }

    #[test]
    fn checkpoint_mode_depends_on_path_and_optional_lt_hashes() {
        assert_eq!(plan(true, true, true).source_copies, 1);
        let alternate = plan(true, false, true);
        assert_eq!(alternate.mode, CheckpointMode::Checkpoint);
        assert_eq!(alternate.source_copies, 2);
        assert!(alternate.copy_checkpoint);
        assert!(alternate.process_lt_hashes);
        assert!(!plan(true, false, false).process_lt_hashes);
    }
}
