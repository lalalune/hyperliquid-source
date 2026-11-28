use node115_abci::abci_hash::{
    ReductionNode, ReductionRow, compute_reduction_node_root, compute_reduction_tree_root,
    encode_reduction_node,
};

#[test]
fn root_leaf_is_hashed_as_a_messagepack_string() {
    let digest = core::array::from_fn(|i| [0x00, 0x0f, 0x80, 0xff][i % 4]);
    let node = ReductionNode::Leaf(digest);
    let preimage = encode_reduction_node(&node).unwrap();
    assert_eq!(&preimage[..4], b"\xd9\x420x");
    assert_eq!(&preimage[4..], b"000f80ff".repeat(8));
    assert_eq!(
        compute_reduction_node_root(&node).unwrap(),
        [
            0x2d, 0x73, 0xd6, 0xe9, 0xda, 0x94, 0x73, 0x82, 0xfd, 0xa7, 0xc6, 0x62, 0x87, 0x9f,
            0xfe, 0xcc, 0xc7, 0x12, 0xdf, 0x63, 0xb, 0xeb, 0xe6, 0xed, 0xdb, 0x6d, 0xd0, 0x4c,
            0xdd, 0xb3, 0xc1, 0x79
        ],
    );
    assert_ne!(compute_reduction_node_root(&node).unwrap(), digest);
}

#[test]
fn nested_root_uses_the_existing_reduction_tree_contract() {
    let rows = vec![ReductionRow {
        index: 3,
        value: ReductionNode::Leaf([0xab; 32]),
    }];
    let expected = compute_reduction_tree_root(&rows).unwrap();
    assert_eq!(
        compute_reduction_node_root(&ReductionNode::Nested(rows)).unwrap(),
        expected
    );
}
