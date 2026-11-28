use node115_abci::abci_hash::{
    CaptureSlot, ROOT_CAPTURE_SLOT_COUNT, ReductionNode, ReductionRow, blake3_hash,
    compute_reduction_tree_root, encode_reduction_tree, reduce_top_level_capture,
};

#[test]
fn capture_preserves_sparse_native_indices_and_nested_rows() {
    let mut slots: [CaptureSlot; ROOT_CAPTURE_SLOT_COUNT] =
        std::array::from_fn(|_| CaptureSlot::Empty);
    slots[1] = CaptureSlot::Omitted;
    slots[2] = CaptureSlot::Value(ReductionNode::Leaf([0xab; 32]));
    slots[17] = CaptureSlot::Value(ReductionNode::Nested(Vec::new()));
    slots[57] = CaptureSlot::Omitted;
    slots[58] = CaptureSlot::Value(ReductionNode::Nested(vec![ReductionRow {
        index: 256,
        value: ReductionNode::Leaf([0xcd; 32]),
    }]));

    let rows = reduce_top_level_capture(slots);
    assert_eq!(
        rows.iter().map(|row| row.index).collect::<Vec<_>>(),
        [2, 17, 58],
    );
    let mut expected = b"\x93\x92\x02\xd9\x420x".to_vec();
    expected.extend_from_slice(b"ab".repeat(32).as_slice());
    expected.extend_from_slice(b"\x92\x11\x90");
    expected.extend_from_slice(b"\x92\x3a\x91\x92\xcd\x01\x00\xd9\x420x");
    expected.extend_from_slice(b"cd".repeat(32).as_slice());
    assert_eq!(encode_reduction_tree(&rows).unwrap(), expected);
    assert_eq!(
        compute_reduction_tree_root(&rows).unwrap(),
        blake3_hash(&expected)
    );
}

#[test]
fn omitted_top_level_slots_leave_an_empty_reduction_array() {
    let slots = std::array::from_fn(|index| {
        if index % 2 == 0 {
            CaptureSlot::Empty
        } else {
            CaptureSlot::Omitted
        }
    });
    let rows = reduce_top_level_capture(slots);
    assert!(rows.is_empty());
    assert_eq!(encode_reduction_tree(&rows).unwrap(), [0x90]);
}
