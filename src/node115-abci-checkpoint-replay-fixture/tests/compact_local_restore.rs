use node115_abci_checkpoint_replay_fixture::{CompactLocalRestoreError, CompactLocalRestoreInput};

fn image(height: u64, tag: u32, target: u64) -> Vec<u8> {
    let mut state = vec![0xa5; 0x42c8];
    for (offset, value) in [
        (0x18, u64::MAX),
        (0x20, 98),
        (0x28, height),
        (0x30, 101),
        (0x10f0, target),
    ] {
        state[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
    state[0x10e8..0x10ec].copy_from_slice(&tag.to_le_bytes());
    state
}

#[test]
fn original_hardfork_and_context_round_remain_distinct() {
    let inputs = CompactLocalRestoreInput::from_checkpoint(&image(77, 1, 77), 77).unwrap();
    assert_eq!(
        inputs,
        CompactLocalRestoreInput {
            height: 77,
            context_round: 101,
            hardfork_version: u64::MAX,
            hardfork_round: 98,
            scheduled_freeze: Some(77),
        }
    );
}

#[test]
fn absent_freeze_ignores_payload_and_tag_padding() {
    let absent = CompactLocalRestoreInput::from_checkpoint(&image(0, 0, u64::MAX), 0).unwrap();
    assert_eq!(absent.scheduled_freeze, None);
    let present = CompactLocalRestoreInput::from_checkpoint(&image(0, 1, 0), 0).unwrap();
    assert_eq!(present.scheduled_freeze, Some(0));
}

#[test]
fn shape_height_and_ordinary_discriminant_are_checked() {
    let state = image(73, 2, 13);
    assert_eq!(
        CompactLocalRestoreInput::from_checkpoint(&state[..0x42c7], 73),
        Err(CompactLocalRestoreError::WrongSize { actual: 0x42c7 })
    );
    assert_eq!(
        CompactLocalRestoreInput::from_checkpoint(&state, 74),
        Err(CompactLocalRestoreError::HeightMismatch {
            expected: 74,
            actual: 73,
        })
    );
    assert_eq!(
        CompactLocalRestoreInput::from_checkpoint(&state, 73),
        Err(CompactLocalRestoreError::FreezeTag(2))
    );
}
