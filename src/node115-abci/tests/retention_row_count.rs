use node115_abci::engine::{PRUNE_KEEP_EVM_CHECKPOINTS, select_checkpoints_to_prune};

#[test]
fn checkpoint_retention_counts_rows_with_equal_heights() {
    let heights = (1..=100).chain([99, 100]).collect();
    assert_eq!(
        select_checkpoints_to_prune(heights, PRUNE_KEEP_EVM_CHECKPOINTS),
        [1, 2],
    );
    assert_eq!(
        select_checkpoints_to_prune(vec![15, 9, 9, 42], 1),
        [9, 9, 15],
    );
    assert!(select_checkpoints_to_prune(vec![11, 11], 2).is_empty());
}
