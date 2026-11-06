// MIT. Literal transcription of frozen pre-source inputs and expectations.
// No expected result was computed by this transcriber or the implementation.
use super::selected::*;

#[test]
fn frozen_a01() {
let map_rows: [Entry; 0] = [];
let map = WeightMap::Flat(FlatMapView::new(&map_rows, 0, 0).unwrap());
let keys_nodes: [KeyNode<'_>; 0] = [];
let view = KeyTreeView::new(&keys_nodes, None).unwrap();
let mut cursor = KeyCursor::new(&view);
assert_eq!(checked_selected_fold(&map, &mut cursor), FoldOutcome::Complete { sum: 0u64, consumed: 0 });
assert_eq!(cursor.remaining(), 0);
assert_eq!(cursor.last_yielded(), None);
}

#[test]
fn frozen_a02() {
let map_nodes: [MapNode<'_>; 0] = [];
let map = WeightMap::Tree(TreeMapView::new(&map_nodes, None).unwrap());
let keys_values_0: [Key; 2] = [[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2]];
let keys_children_0: [usize; 0] = [];
let keys_nodes: [KeyNode<'_>; 1] = [KeyNode { keys: &keys_values_0, children: &keys_children_0, parent: None }];
let view = KeyTreeView::new(&keys_nodes, Some(0)).unwrap();
let mut cursor = KeyCursor::new(&view);
assert_eq!(checked_selected_fold(&map, &mut cursor), FoldOutcome::Complete { sum: 0u64, consumed: 2 });
assert_eq!(cursor.remaining(), 0);
assert_eq!(cursor.last_yielded(), Some(Position { node: 0, index: 1 }));
}

#[test]
fn frozen_a03() {
let map_rows: [Entry; 1] = [Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1], weight: 0u64 }];
let map = WeightMap::Flat(FlatMapView::new(&map_rows, 0, 1).unwrap());
let keys_values_0: [Key; 1] = [[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]];
let keys_children_0: [usize; 0] = [];
let keys_nodes: [KeyNode<'_>; 1] = [KeyNode { keys: &keys_values_0, children: &keys_children_0, parent: None }];
let view = KeyTreeView::new(&keys_nodes, Some(0)).unwrap();
let mut cursor = KeyCursor::new(&view);
assert_eq!(checked_selected_fold(&map, &mut cursor), FoldOutcome::Complete { sum: 0u64, consumed: 1 });
assert_eq!(cursor.remaining(), 0);
assert_eq!(cursor.last_yielded(), Some(Position { node: 0, index: 0 }));
}

#[test]
fn frozen_a04() {
let map_rows: [Entry; 2] = [Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1], weight: 18446744073709551615u64 },Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2], weight: 0u64 }];
let map = WeightMap::Flat(FlatMapView::new(&map_rows, 0, 2).unwrap());
let keys_values_0: [Key; 2] = [[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2]];
let keys_children_0: [usize; 0] = [];
let keys_nodes: [KeyNode<'_>; 1] = [KeyNode { keys: &keys_values_0, children: &keys_children_0, parent: None }];
let view = KeyTreeView::new(&keys_nodes, Some(0)).unwrap();
let mut cursor = KeyCursor::new(&view);
assert_eq!(checked_selected_fold(&map, &mut cursor), FoldOutcome::Complete { sum: 18446744073709551615u64, consumed: 2 });
assert_eq!(cursor.remaining(), 0);
assert_eq!(cursor.last_yielded(), Some(Position { node: 0, index: 1 }));
}

#[test]
fn frozen_a05() {
let map_rows: [Entry; 3] = [Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1], weight: 18446744073709551615u64 },Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2], weight: 1u64 },Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,3], weight: 7u64 }];
let map = WeightMap::Flat(FlatMapView::new(&map_rows, 0, 3).unwrap());
let keys_values_0: [Key; 1] = [[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2]];
let keys_children_0: [usize; 2] = [1,2];
let keys_values_1: [Key; 1] = [[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]];
let keys_children_1: [usize; 0] = [];
let keys_values_2: [Key; 1] = [[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,3]];
let keys_children_2: [usize; 0] = [];
let keys_nodes: [KeyNode<'_>; 3] = [KeyNode { keys: &keys_values_0, children: &keys_children_0, parent: None },KeyNode { keys: &keys_values_1, children: &keys_children_1, parent: Some(ParentLink { node: 0, edge: 0 }) },KeyNode { keys: &keys_values_2, children: &keys_children_2, parent: Some(ParentLink { node: 0, edge: 1 }) }];
let view = KeyTreeView::new(&keys_nodes, Some(0)).unwrap();
let mut cursor = KeyCursor::new(&view);
assert_eq!(checked_selected_fold(&map, &mut cursor), FoldOutcome::Overflow { wrapped_sum: 0u64, consumed: 2 });
assert_eq!(cursor.remaining(), 1);
assert_eq!(cursor.last_yielded(), Some(Position { node: 0, index: 0 }));
assert_eq!(checked_selected_fold(&map, &mut cursor), FoldOutcome::Complete { sum: 7u64, consumed: 1 });
assert_eq!(cursor.remaining(), 0);
assert_eq!(cursor.last_yielded(), Some(Position { node: 2, index: 0 }));
assert_eq!(checked_selected_fold(&map, &mut cursor), FoldOutcome::Complete { sum: 0u64, consumed: 0 });
assert_eq!(cursor.remaining(), 0);
assert_eq!(cursor.last_yielded(), Some(Position { node: 2, index: 0 }));
}

#[test]
fn frozen_a06() {
let map_rows: [Entry; 3] = [Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1], weight: 18446744073709551614u64 },Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2], weight: 3u64 },Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,3], weight: 9u64 }];
let map = WeightMap::Flat(FlatMapView::new(&map_rows, 0, 3).unwrap());
let keys_values_0: [Key; 3] = [[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,3]];
let keys_children_0: [usize; 0] = [];
let keys_nodes: [KeyNode<'_>; 1] = [KeyNode { keys: &keys_values_0, children: &keys_children_0, parent: None }];
let view = KeyTreeView::new(&keys_nodes, Some(0)).unwrap();
let mut cursor = KeyCursor::new(&view);
assert_eq!(checked_selected_fold(&map, &mut cursor), FoldOutcome::Overflow { wrapped_sum: 1u64, consumed: 2 });
assert_eq!(cursor.remaining(), 1);
assert_eq!(cursor.last_yielded(), Some(Position { node: 0, index: 1 }));
}

#[test]
fn frozen_a07() {
let map_rows: [Entry; 2] = [Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2], weight: 18446744073709551615u64 },Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,4], weight: 1u64 }];
let map = WeightMap::Flat(FlatMapView::new(&map_rows, 0, 2).unwrap());
let keys_values_0: [Key; 4] = [[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,3],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,4]];
let keys_children_0: [usize; 0] = [];
let keys_nodes: [KeyNode<'_>; 1] = [KeyNode { keys: &keys_values_0, children: &keys_children_0, parent: None }];
let view = KeyTreeView::new(&keys_nodes, Some(0)).unwrap();
let mut cursor = KeyCursor::new(&view);
assert_eq!(checked_selected_fold(&map, &mut cursor), FoldOutcome::Overflow { wrapped_sum: 0u64, consumed: 4 });
assert_eq!(cursor.remaining(), 0);
assert_eq!(cursor.last_yielded(), Some(Position { node: 0, index: 3 }));
}

#[test]
fn frozen_a08() {
let map_rows: [Entry; 2] = [Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1], weight: 5u64 },Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,3], weight: 7u64 }];
let map = WeightMap::Flat(FlatMapView::new(&map_rows, 0, 2).unwrap());
let keys_values_0: [Key; 3] = [[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,3],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,3]];
let keys_children_0: [usize; 0] = [];
let keys_nodes: [KeyNode<'_>; 1] = [KeyNode { keys: &keys_values_0, children: &keys_children_0, parent: None }];
let view = KeyTreeView::new(&keys_nodes, Some(0)).unwrap();
let mut cursor = KeyCursor::new(&view);
assert_eq!(checked_selected_fold(&map, &mut cursor), FoldOutcome::Complete { sum: 19u64, consumed: 3 });
assert_eq!(cursor.remaining(), 0);
assert_eq!(cursor.last_yielded(), Some(Position { node: 0, index: 2 }));
}

#[test]
fn frozen_a09() {
let map_rows: [Entry; 2] = [Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1], weight: 18446744073709551615u64 },Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2], weight: 3u64 }];
let map = WeightMap::Flat(FlatMapView::new(&map_rows, 0, 2).unwrap());
let keys_values_0: [Key; 3] = [[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2]];
let keys_children_0: [usize; 0] = [];
let keys_nodes: [KeyNode<'_>; 1] = [KeyNode { keys: &keys_values_0, children: &keys_children_0, parent: None }];
let view = KeyTreeView::new(&keys_nodes, Some(0)).unwrap();
let mut cursor = KeyCursor::new(&view);
assert_eq!(checked_selected_fold(&map, &mut cursor), FoldOutcome::Overflow { wrapped_sum: 18446744073709551614u64, consumed: 2 });
assert_eq!(cursor.remaining(), 1);
assert_eq!(cursor.last_yielded(), Some(Position { node: 0, index: 1 }));
}

#[test]
fn frozen_f01() {
let map_rows: [Entry; 3] = [Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,3], weight: 300u64 },Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,3], weight: 30u64 },Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,3], weight: 31u64 }];
let map = WeightMap::Flat(FlatMapView::new(&map_rows, 0, 3).unwrap());
let keys_values_0: [Key; 1] = [[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,3]];
let keys_children_0: [usize; 0] = [];
let keys_nodes: [KeyNode<'_>; 1] = [KeyNode { keys: &keys_values_0, children: &keys_children_0, parent: None }];
let view = KeyTreeView::new(&keys_nodes, Some(0)).unwrap();
let mut cursor = KeyCursor::new(&view);
assert_eq!(checked_selected_fold(&map, &mut cursor), FoldOutcome::Complete { sum: 31u64, consumed: 1 });
assert_eq!(cursor.remaining(), 0);
assert_eq!(cursor.last_yielded(), Some(Position { node: 0, index: 0 }));
}

#[test]
fn frozen_f02() {
let map_rows: [Entry; 5] = [Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,3], weight: 30u64 },Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,3], weight: 31u64 },Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,5], weight: 50u64 },Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1], weight: 10u64 },Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,3], weight: 300u64 }];
let map = WeightMap::Flat(FlatMapView::new(&map_rows, 3, 5).unwrap());
let keys_values_0: [Key; 1] = [[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,3]];
let keys_children_0: [usize; 0] = [];
let keys_nodes: [KeyNode<'_>; 1] = [KeyNode { keys: &keys_values_0, children: &keys_children_0, parent: None }];
let view = KeyTreeView::new(&keys_nodes, Some(0)).unwrap();
let mut cursor = KeyCursor::new(&view);
assert_eq!(checked_selected_fold(&map, &mut cursor), FoldOutcome::Complete { sum: 30u64, consumed: 1 });
assert_eq!(cursor.remaining(), 0);
assert_eq!(cursor.last_yielded(), Some(Position { node: 0, index: 0 }));
}

#[test]
fn frozen_f03() {
let map_rows: [Entry; 5] = [Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,3], weight: 30u64 },Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,3], weight: 31u64 },Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,5], weight: 50u64 },Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1], weight: 10u64 },Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,3], weight: 300u64 }];
let map = WeightMap::Flat(FlatMapView::new(&map_rows, 3, 5).unwrap());
let keys_values_0: [Key; 3] = [[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,4],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,5]];
let keys_children_0: [usize; 0] = [];
let keys_nodes: [KeyNode<'_>; 1] = [KeyNode { keys: &keys_values_0, children: &keys_children_0, parent: None }];
let view = KeyTreeView::new(&keys_nodes, Some(0)).unwrap();
let mut cursor = KeyCursor::new(&view);
assert_eq!(checked_selected_fold(&map, &mut cursor), FoldOutcome::Complete { sum: 60u64, consumed: 3 });
assert_eq!(cursor.remaining(), 0);
assert_eq!(cursor.last_yielded(), Some(Position { node: 0, index: 2 }));
}

#[test]
fn frozen_f04() {
let map_rows: [Entry; 7] = [Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,4], weight: 40u64 },Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,6], weight: 60u64 },Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,6], weight: 61u64 },Entry { key: [255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255], weight: 999u64 },Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1], weight: 10u64 },Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2], weight: 20u64 },Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2], weight: 21u64 }];
let map = WeightMap::Flat(FlatMapView::new(&map_rows, 4, 6).unwrap());
let keys_values_0: [Key; 4] = [[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,4],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,6]];
let keys_children_0: [usize; 0] = [];
let keys_nodes: [KeyNode<'_>; 1] = [KeyNode { keys: &keys_values_0, children: &keys_children_0, parent: None }];
let view = KeyTreeView::new(&keys_nodes, Some(0)).unwrap();
let mut cursor = KeyCursor::new(&view);
assert_eq!(checked_selected_fold(&map, &mut cursor), FoldOutcome::Complete { sum: 132u64, consumed: 4 });
assert_eq!(cursor.remaining(), 0);
assert_eq!(cursor.last_yielded(), Some(Position { node: 0, index: 3 }));
}

#[test]
fn frozen_f05() {
let map_rows: [Entry; 4] = [Entry { key: [255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255], weight: 999u64 },Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2], weight: 20u64 },Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,4], weight: 40u64 },Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0], weight: 999u64 }];
let map = WeightMap::Flat(FlatMapView::new(&map_rows, 1, 2).unwrap());
let keys_values_0: [Key; 5] = [[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,3],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,4],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,5]];
let keys_children_0: [usize; 0] = [];
let keys_nodes: [KeyNode<'_>; 1] = [KeyNode { keys: &keys_values_0, children: &keys_children_0, parent: None }];
let view = KeyTreeView::new(&keys_nodes, Some(0)).unwrap();
let mut cursor = KeyCursor::new(&view);
assert_eq!(checked_selected_fold(&map, &mut cursor), FoldOutcome::Complete { sum: 60u64, consumed: 5 });
assert_eq!(cursor.remaining(), 0);
assert_eq!(cursor.last_yielded(), Some(Position { node: 0, index: 4 }));
}

#[test]
fn frozen_f06() {
let map_rows: [Entry; 1] = [Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,8], weight: 80u64 }];
let map = WeightMap::Flat(FlatMapView::new(&map_rows, 0, 1).unwrap());
let keys_values_0: [Key; 3] = [[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,8],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,7],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,9]];
let keys_children_0: [usize; 0] = [];
let keys_nodes: [KeyNode<'_>; 1] = [KeyNode { keys: &keys_values_0, children: &keys_children_0, parent: None }];
let view = KeyTreeView::new(&keys_nodes, Some(0)).unwrap();
let mut cursor = KeyCursor::new(&view);
assert_eq!(checked_selected_fold(&map, &mut cursor), FoldOutcome::Complete { sum: 80u64, consumed: 3 });
assert_eq!(cursor.remaining(), 0);
assert_eq!(cursor.last_yielded(), Some(Position { node: 0, index: 2 }));
}

#[test]
fn frozen_f07() {
let map_rows: [Entry; 3] = [Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,3], weight: 3u64 },Entry { key: [255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255], weight: 999u64 },Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1], weight: 2u64 }];
let map = WeightMap::Flat(FlatMapView::new(&map_rows, 2, 2).unwrap());
let keys_values_0: [Key; 4] = [[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,3],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,4]];
let keys_children_0: [usize; 0] = [];
let keys_nodes: [KeyNode<'_>; 1] = [KeyNode { keys: &keys_values_0, children: &keys_children_0, parent: None }];
let view = KeyTreeView::new(&keys_nodes, Some(0)).unwrap();
let mut cursor = KeyCursor::new(&view);
assert_eq!(checked_selected_fold(&map, &mut cursor), FoldOutcome::Complete { sum: 5u64, consumed: 4 });
assert_eq!(cursor.remaining(), 0);
assert_eq!(cursor.last_yielded(), Some(Position { node: 0, index: 3 }));
}

#[test]
fn frozen_t01() {
let map_values_0: [Entry; 2] = [Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,3], weight: 30u64 },Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,3], weight: 31u64 }];
let map_children_0: [usize; 3] = [1,2,3];
let map_values_1: [Entry; 2] = [Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1], weight: 10u64 },Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,3], weight: 300u64 }];
let map_children_1: [usize; 0] = [];
let map_values_2: [Entry; 1] = [Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,3], weight: 301u64 }];
let map_children_2: [usize; 0] = [];
let map_values_3: [Entry; 2] = [Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,3], weight: 302u64 },Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,5], weight: 50u64 }];
let map_children_3: [usize; 0] = [];
let map_nodes: [MapNode<'_>; 4] = [MapNode { entries: &map_values_0, children: &map_children_0, parent: None },MapNode { entries: &map_values_1, children: &map_children_1, parent: Some(ParentLink { node: 0, edge: 0 }) },MapNode { entries: &map_values_2, children: &map_children_2, parent: Some(ParentLink { node: 0, edge: 1 }) },MapNode { entries: &map_values_3, children: &map_children_3, parent: Some(ParentLink { node: 0, edge: 2 }) }];
let map = WeightMap::Tree(TreeMapView::new(&map_nodes, Some(0)).unwrap());
let keys_values_0: [Key; 4] = [[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,3],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,4],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,5]];
let keys_children_0: [usize; 0] = [];
let keys_nodes: [KeyNode<'_>; 1] = [KeyNode { keys: &keys_values_0, children: &keys_children_0, parent: None }];
let view = KeyTreeView::new(&keys_nodes, Some(0)).unwrap();
let mut cursor = KeyCursor::new(&view);
assert_eq!(checked_selected_fold(&map, &mut cursor), FoldOutcome::Complete { sum: 90u64, consumed: 4 });
assert_eq!(cursor.remaining(), 0);
assert_eq!(cursor.last_yielded(), Some(Position { node: 0, index: 3 }));
}

#[test]
fn frozen_t02() {
let map_values_0: [Entry; 1] = [Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2], weight: 20u64 }];
let map_children_0: [usize; 2] = [1,2];
let map_values_1: [Entry; 1] = [Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1], weight: 10u64 }];
let map_children_1: [usize; 0] = [];
let map_values_2: [Entry; 2] = [Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,3], weight: 300u64 },Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,3], weight: 301u64 }];
let map_children_2: [usize; 0] = [];
let map_nodes: [MapNode<'_>; 3] = [MapNode { entries: &map_values_0, children: &map_children_0, parent: None },MapNode { entries: &map_values_1, children: &map_children_1, parent: Some(ParentLink { node: 0, edge: 0 }) },MapNode { entries: &map_values_2, children: &map_children_2, parent: Some(ParentLink { node: 0, edge: 1 }) }];
let map = WeightMap::Tree(TreeMapView::new(&map_nodes, Some(0)).unwrap());
let keys_values_0: [Key; 1] = [[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,3]];
let keys_children_0: [usize; 0] = [];
let keys_nodes: [KeyNode<'_>; 1] = [KeyNode { keys: &keys_values_0, children: &keys_children_0, parent: None }];
let view = KeyTreeView::new(&keys_nodes, Some(0)).unwrap();
let mut cursor = KeyCursor::new(&view);
assert_eq!(checked_selected_fold(&map, &mut cursor), FoldOutcome::Complete { sum: 300u64, consumed: 1 });
assert_eq!(cursor.remaining(), 0);
assert_eq!(cursor.last_yielded(), Some(Position { node: 0, index: 0 }));
}

#[test]
fn frozen_t03() {
let map_values_0: [Entry; 2] = [Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2], weight: 20u64 },Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,4], weight: 40u64 }];
let map_children_0: [usize; 3] = [1,2,3];
let map_values_1: [Entry; 1] = [Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1], weight: 10u64 }];
let map_children_1: [usize; 0] = [];
let map_values_2: [Entry; 1] = [Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,3], weight: 30u64 }];
let map_children_2: [usize; 0] = [];
let map_values_3: [Entry; 1] = [Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,5], weight: 50u64 }];
let map_children_3: [usize; 0] = [];
let map_nodes: [MapNode<'_>; 4] = [MapNode { entries: &map_values_0, children: &map_children_0, parent: None },MapNode { entries: &map_values_1, children: &map_children_1, parent: Some(ParentLink { node: 0, edge: 0 }) },MapNode { entries: &map_values_2, children: &map_children_2, parent: Some(ParentLink { node: 0, edge: 1 }) },MapNode { entries: &map_values_3, children: &map_children_3, parent: Some(ParentLink { node: 0, edge: 2 }) }];
let map = WeightMap::Tree(TreeMapView::new(&map_nodes, Some(0)).unwrap());
let keys_values_0: [Key; 7] = [[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,3],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,4],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,5],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,6]];
let keys_children_0: [usize; 0] = [];
let keys_nodes: [KeyNode<'_>; 1] = [KeyNode { keys: &keys_values_0, children: &keys_children_0, parent: None }];
let view = KeyTreeView::new(&keys_nodes, Some(0)).unwrap();
let mut cursor = KeyCursor::new(&view);
assert_eq!(checked_selected_fold(&map, &mut cursor), FoldOutcome::Complete { sum: 150u64, consumed: 7 });
assert_eq!(cursor.remaining(), 0);
assert_eq!(cursor.last_yielded(), Some(Position { node: 0, index: 6 }));
}

#[test]
fn frozen_t04() {
let map_values_0: [Entry; 0] = [];
let map_children_0: [usize; 1] = [1];
let map_values_1: [Entry; 1] = [Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1], weight: 9u64 }];
let map_children_1: [usize; 0] = [];
let map_nodes: [MapNode<'_>; 2] = [MapNode { entries: &map_values_0, children: &map_children_0, parent: None },MapNode { entries: &map_values_1, children: &map_children_1, parent: Some(ParentLink { node: 0, edge: 0 }) }];
let map = WeightMap::Tree(TreeMapView::new(&map_nodes, Some(0)).unwrap());
let keys_values_0: [Key; 1] = [[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]];
let keys_children_0: [usize; 0] = [];
let keys_nodes: [KeyNode<'_>; 1] = [KeyNode { keys: &keys_values_0, children: &keys_children_0, parent: None }];
let view = KeyTreeView::new(&keys_nodes, Some(0)).unwrap();
let mut cursor = KeyCursor::new(&view);
assert_eq!(checked_selected_fold(&map, &mut cursor), FoldOutcome::Complete { sum: 9u64, consumed: 1 });
assert_eq!(cursor.remaining(), 0);
assert_eq!(cursor.last_yielded(), Some(Position { node: 0, index: 0 }));
}

#[test]
fn frozen_t05() {
let map_values_0: [Entry; 11] = [Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1], weight: 1u64 },Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2], weight: 2u64 },Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,3], weight: 3u64 },Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,4], weight: 4u64 },Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,5], weight: 5u64 },Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,6], weight: 6u64 },Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,7], weight: 7u64 },Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,8], weight: 8u64 },Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,9], weight: 9u64 },Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,10], weight: 10u64 },Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,11], weight: 11u64 }];
let map_children_0: [usize; 0] = [];
let map_nodes: [MapNode<'_>; 1] = [MapNode { entries: &map_values_0, children: &map_children_0, parent: None }];
let map = WeightMap::Tree(TreeMapView::new(&map_nodes, Some(0)).unwrap());
let keys_values_0: [Key; 5] = [[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,6],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,11],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,12]];
let keys_children_0: [usize; 0] = [];
let keys_nodes: [KeyNode<'_>; 1] = [KeyNode { keys: &keys_values_0, children: &keys_children_0, parent: None }];
let view = KeyTreeView::new(&keys_nodes, Some(0)).unwrap();
let mut cursor = KeyCursor::new(&view);
assert_eq!(checked_selected_fold(&map, &mut cursor), FoldOutcome::Complete { sum: 18u64, consumed: 5 });
assert_eq!(cursor.remaining(), 0);
assert_eq!(cursor.last_yielded(), Some(Position { node: 0, index: 4 }));
}

#[test]
fn frozen_k01() {
let map_rows: [Entry; 7] = [Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1], weight: 1u64 },Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2], weight: 1u64 },Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,3], weight: 1u64 },Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,4], weight: 1u64 },Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,5], weight: 1u64 },Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,6], weight: 1u64 },Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,7], weight: 1u64 }];
let map = WeightMap::Flat(FlatMapView::new(&map_rows, 0, 7).unwrap());
let keys_values_0: [Key; 1] = [[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,4]];
let keys_children_0: [usize; 2] = [1,2];
let keys_values_1: [Key; 1] = [[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2]];
let keys_children_1: [usize; 2] = [3,4];
let keys_values_2: [Key; 1] = [[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,6]];
let keys_children_2: [usize; 2] = [5,6];
let keys_values_3: [Key; 1] = [[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]];
let keys_children_3: [usize; 0] = [];
let keys_values_4: [Key; 1] = [[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,3]];
let keys_children_4: [usize; 0] = [];
let keys_values_5: [Key; 1] = [[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,5]];
let keys_children_5: [usize; 0] = [];
let keys_values_6: [Key; 1] = [[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,7]];
let keys_children_6: [usize; 0] = [];
let keys_nodes: [KeyNode<'_>; 7] = [KeyNode { keys: &keys_values_0, children: &keys_children_0, parent: None },KeyNode { keys: &keys_values_1, children: &keys_children_1, parent: Some(ParentLink { node: 0, edge: 0 }) },KeyNode { keys: &keys_values_2, children: &keys_children_2, parent: Some(ParentLink { node: 0, edge: 1 }) },KeyNode { keys: &keys_values_3, children: &keys_children_3, parent: Some(ParentLink { node: 1, edge: 0 }) },KeyNode { keys: &keys_values_4, children: &keys_children_4, parent: Some(ParentLink { node: 1, edge: 1 }) },KeyNode { keys: &keys_values_5, children: &keys_children_5, parent: Some(ParentLink { node: 2, edge: 0 }) },KeyNode { keys: &keys_values_6, children: &keys_children_6, parent: Some(ParentLink { node: 2, edge: 1 }) }];
let view = KeyTreeView::new(&keys_nodes, Some(0)).unwrap();
let mut cursor = KeyCursor::new(&view);
assert_eq!(checked_selected_fold(&map, &mut cursor), FoldOutcome::Complete { sum: 7u64, consumed: 7 });
assert_eq!(cursor.remaining(), 0);
assert_eq!(cursor.last_yielded(), Some(Position { node: 6, index: 0 }));
}

#[test]
fn frozen_k02() {
let map_rows: [Entry; 7] = [Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1], weight: 18446744073709551615u64 },Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2], weight: 0u64 },Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,3], weight: 1u64 },Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,4], weight: 1u64 },Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,5], weight: 1u64 },Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,6], weight: 1u64 },Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,7], weight: 1u64 }];
let map = WeightMap::Flat(FlatMapView::new(&map_rows, 0, 7).unwrap());
let keys_values_0: [Key; 1] = [[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,4]];
let keys_children_0: [usize; 2] = [1,2];
let keys_values_1: [Key; 1] = [[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2]];
let keys_children_1: [usize; 2] = [3,4];
let keys_values_2: [Key; 1] = [[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,6]];
let keys_children_2: [usize; 2] = [5,6];
let keys_values_3: [Key; 1] = [[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]];
let keys_children_3: [usize; 0] = [];
let keys_values_4: [Key; 1] = [[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,3]];
let keys_children_4: [usize; 0] = [];
let keys_values_5: [Key; 1] = [[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,5]];
let keys_children_5: [usize; 0] = [];
let keys_values_6: [Key; 1] = [[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,7]];
let keys_children_6: [usize; 0] = [];
let keys_nodes: [KeyNode<'_>; 7] = [KeyNode { keys: &keys_values_0, children: &keys_children_0, parent: None },KeyNode { keys: &keys_values_1, children: &keys_children_1, parent: Some(ParentLink { node: 0, edge: 0 }) },KeyNode { keys: &keys_values_2, children: &keys_children_2, parent: Some(ParentLink { node: 0, edge: 1 }) },KeyNode { keys: &keys_values_3, children: &keys_children_3, parent: Some(ParentLink { node: 1, edge: 0 }) },KeyNode { keys: &keys_values_4, children: &keys_children_4, parent: Some(ParentLink { node: 1, edge: 1 }) },KeyNode { keys: &keys_values_5, children: &keys_children_5, parent: Some(ParentLink { node: 2, edge: 0 }) },KeyNode { keys: &keys_values_6, children: &keys_children_6, parent: Some(ParentLink { node: 2, edge: 1 }) }];
let view = KeyTreeView::new(&keys_nodes, Some(0)).unwrap();
let mut cursor = KeyCursor::new(&view);
assert_eq!(checked_selected_fold(&map, &mut cursor), FoldOutcome::Overflow { wrapped_sum: 0u64, consumed: 3 });
assert_eq!(cursor.remaining(), 4);
assert_eq!(cursor.last_yielded(), Some(Position { node: 4, index: 0 }));
assert_eq!(checked_selected_fold(&map, &mut cursor), FoldOutcome::Complete { sum: 4u64, consumed: 4 });
assert_eq!(cursor.remaining(), 0);
assert_eq!(cursor.last_yielded(), Some(Position { node: 6, index: 0 }));
}

#[test]
fn frozen_k03() {
let map_rows: [Entry; 2] = [Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2], weight: 20u64 },Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,3], weight: 30u64 }];
let map = WeightMap::Flat(FlatMapView::new(&map_rows, 0, 2).unwrap());
let keys_values_0: [Key; 1] = [[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2]];
let keys_children_0: [usize; 2] = [1,2];
let keys_values_1: [Key; 0] = [];
let keys_children_1: [usize; 0] = [];
let keys_values_2: [Key; 1] = [[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,3]];
let keys_children_2: [usize; 0] = [];
let keys_nodes: [KeyNode<'_>; 3] = [KeyNode { keys: &keys_values_0, children: &keys_children_0, parent: None },KeyNode { keys: &keys_values_1, children: &keys_children_1, parent: Some(ParentLink { node: 0, edge: 0 }) },KeyNode { keys: &keys_values_2, children: &keys_children_2, parent: Some(ParentLink { node: 0, edge: 1 }) }];
let view = KeyTreeView::new(&keys_nodes, Some(0)).unwrap();
let mut cursor = KeyCursor::new(&view);
assert_eq!(checked_selected_fold(&map, &mut cursor), FoldOutcome::Complete { sum: 50u64, consumed: 2 });
assert_eq!(cursor.remaining(), 0);
assert_eq!(cursor.last_yielded(), Some(Position { node: 2, index: 0 }));
}

#[test]
fn frozen_k04_depth8() {
let map_rows: [Entry; 1] = [Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1], weight: 9u64 }];
let map = WeightMap::Flat(FlatMapView::new(&map_rows, 0, 1).unwrap());
let keys_values_0: [Key; 0] = [];
let keys_children_0: [usize; 1] = [1];
let keys_values_1: [Key; 0] = [];
let keys_children_1: [usize; 1] = [2];
let keys_values_2: [Key; 0] = [];
let keys_children_2: [usize; 1] = [3];
let keys_values_3: [Key; 0] = [];
let keys_children_3: [usize; 1] = [4];
let keys_values_4: [Key; 0] = [];
let keys_children_4: [usize; 1] = [5];
let keys_values_5: [Key; 0] = [];
let keys_children_5: [usize; 1] = [6];
let keys_values_6: [Key; 0] = [];
let keys_children_6: [usize; 1] = [7];
let keys_values_7: [Key; 0] = [];
let keys_children_7: [usize; 1] = [8];
let keys_values_8: [Key; 1] = [[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]];
let keys_children_8: [usize; 0] = [];
let keys_nodes: [KeyNode<'_>; 9] = [KeyNode { keys: &keys_values_0, children: &keys_children_0, parent: None },KeyNode { keys: &keys_values_1, children: &keys_children_1, parent: Some(ParentLink { node: 0, edge: 0 }) },KeyNode { keys: &keys_values_2, children: &keys_children_2, parent: Some(ParentLink { node: 1, edge: 0 }) },KeyNode { keys: &keys_values_3, children: &keys_children_3, parent: Some(ParentLink { node: 2, edge: 0 }) },KeyNode { keys: &keys_values_4, children: &keys_children_4, parent: Some(ParentLink { node: 3, edge: 0 }) },KeyNode { keys: &keys_values_5, children: &keys_children_5, parent: Some(ParentLink { node: 4, edge: 0 }) },KeyNode { keys: &keys_values_6, children: &keys_children_6, parent: Some(ParentLink { node: 5, edge: 0 }) },KeyNode { keys: &keys_values_7, children: &keys_children_7, parent: Some(ParentLink { node: 6, edge: 0 }) },KeyNode { keys: &keys_values_8, children: &keys_children_8, parent: Some(ParentLink { node: 7, edge: 0 }) }];
let view = KeyTreeView::new(&keys_nodes, Some(0)).unwrap();
let mut cursor = KeyCursor::new(&view);
assert_eq!(checked_selected_fold(&map, &mut cursor), FoldOutcome::Complete { sum: 9u64, consumed: 1 });
assert_eq!(cursor.remaining(), 0);
assert_eq!(cursor.last_yielded(), Some(Position { node: 8, index: 0 }));
}

#[test]
fn frozen_k04_depth9() {
let map_rows: [Entry; 1] = [Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1], weight: 9u64 }];
let map = WeightMap::Flat(FlatMapView::new(&map_rows, 0, 1).unwrap());
let keys_values_0: [Key; 0] = [];
let keys_children_0: [usize; 1] = [1];
let keys_values_1: [Key; 0] = [];
let keys_children_1: [usize; 1] = [2];
let keys_values_2: [Key; 0] = [];
let keys_children_2: [usize; 1] = [3];
let keys_values_3: [Key; 0] = [];
let keys_children_3: [usize; 1] = [4];
let keys_values_4: [Key; 0] = [];
let keys_children_4: [usize; 1] = [5];
let keys_values_5: [Key; 0] = [];
let keys_children_5: [usize; 1] = [6];
let keys_values_6: [Key; 0] = [];
let keys_children_6: [usize; 1] = [7];
let keys_values_7: [Key; 0] = [];
let keys_children_7: [usize; 1] = [8];
let keys_values_8: [Key; 0] = [];
let keys_children_8: [usize; 1] = [9];
let keys_values_9: [Key; 1] = [[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]];
let keys_children_9: [usize; 0] = [];
let keys_nodes: [KeyNode<'_>; 10] = [KeyNode { keys: &keys_values_0, children: &keys_children_0, parent: None },KeyNode { keys: &keys_values_1, children: &keys_children_1, parent: Some(ParentLink { node: 0, edge: 0 }) },KeyNode { keys: &keys_values_2, children: &keys_children_2, parent: Some(ParentLink { node: 1, edge: 0 }) },KeyNode { keys: &keys_values_3, children: &keys_children_3, parent: Some(ParentLink { node: 2, edge: 0 }) },KeyNode { keys: &keys_values_4, children: &keys_children_4, parent: Some(ParentLink { node: 3, edge: 0 }) },KeyNode { keys: &keys_values_5, children: &keys_children_5, parent: Some(ParentLink { node: 4, edge: 0 }) },KeyNode { keys: &keys_values_6, children: &keys_children_6, parent: Some(ParentLink { node: 5, edge: 0 }) },KeyNode { keys: &keys_values_7, children: &keys_children_7, parent: Some(ParentLink { node: 6, edge: 0 }) },KeyNode { keys: &keys_values_8, children: &keys_children_8, parent: Some(ParentLink { node: 7, edge: 0 }) },KeyNode { keys: &keys_values_9, children: &keys_children_9, parent: Some(ParentLink { node: 8, edge: 0 }) }];
let view = KeyTreeView::new(&keys_nodes, Some(0)).unwrap();
let mut cursor = KeyCursor::new(&view);
assert_eq!(checked_selected_fold(&map, &mut cursor), FoldOutcome::Complete { sum: 9u64, consumed: 1 });
assert_eq!(cursor.remaining(), 0);
assert_eq!(cursor.last_yielded(), Some(Position { node: 9, index: 0 }));
}

#[test]
fn frozen_k05() {
let map_rows: [Entry; 1] = [Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1], weight: 1u64 }];
let map = WeightMap::Flat(FlatMapView::new(&map_rows, 0, 1).unwrap());
let keys_values_0: [Key; 11] = [[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]];
let keys_children_0: [usize; 0] = [];
let keys_nodes: [KeyNode<'_>; 1] = [KeyNode { keys: &keys_values_0, children: &keys_children_0, parent: None }];
let view = KeyTreeView::new(&keys_nodes, Some(0)).unwrap();
let mut cursor = KeyCursor::new(&view);
assert_eq!(checked_selected_fold(&map, &mut cursor), FoldOutcome::Complete { sum: 11u64, consumed: 11 });
assert_eq!(cursor.remaining(), 0);
assert_eq!(cursor.last_yielded(), Some(Position { node: 0, index: 10 }));
}

#[test]
fn frozen_u01() {
let map_rows: [Entry; 2] = [Entry { key: [0,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255], weight: 2u64 },Entry { key: [1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0], weight: 3u64 }];
let map = WeightMap::Flat(FlatMapView::new(&map_rows, 0, 2).unwrap());
let keys_values_0: [Key; 2] = [[1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],[0,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255]];
let keys_children_0: [usize; 0] = [];
let keys_nodes: [KeyNode<'_>; 1] = [KeyNode { keys: &keys_values_0, children: &keys_children_0, parent: None }];
let view = KeyTreeView::new(&keys_nodes, Some(0)).unwrap();
let mut cursor = KeyCursor::new(&view);
assert_eq!(checked_selected_fold(&map, &mut cursor), FoldOutcome::Complete { sum: 5u64, consumed: 2 });
assert_eq!(cursor.remaining(), 0);
assert_eq!(cursor.last_yielded(), Some(Position { node: 0, index: 1 }));
}

#[test]
fn frozen_u02() {
let map_rows: [Entry; 3] = [Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,127], weight: 1u64 },Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,128], weight: 2u64 },Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,255], weight: 4u64 }];
let map = WeightMap::Flat(FlatMapView::new(&map_rows, 0, 3).unwrap());
let keys_values_0: [Key; 3] = [[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,255],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,128],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,127]];
let keys_children_0: [usize; 0] = [];
let keys_nodes: [KeyNode<'_>; 1] = [KeyNode { keys: &keys_values_0, children: &keys_children_0, parent: None }];
let view = KeyTreeView::new(&keys_nodes, Some(0)).unwrap();
let mut cursor = KeyCursor::new(&view);
assert_eq!(checked_selected_fold(&map, &mut cursor), FoldOutcome::Complete { sum: 7u64, consumed: 3 });
assert_eq!(cursor.remaining(), 0);
assert_eq!(cursor.last_yielded(), Some(Position { node: 0, index: 2 }));
}

#[test]
fn host_r01() {
let rows: [Entry; 2] = [Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2], weight: 2u64 },Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1], weight: 1u64 }];
assert_eq!(FlatMapView::new(&rows, 2, 2).unwrap_err(), AdmissionError::Bounds);
}

#[test]
fn host_r02() {
let rows: [Entry; 2] = [Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1], weight: 1u64 },Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2], weight: 2u64 }];
assert_eq!(FlatMapView::new(&rows, 0, 3).unwrap_err(), AdmissionError::Bounds);
}

#[test]
fn host_r03() {
let rows: [Entry; 0] = [];
assert_eq!(FlatMapView::new(&rows, 1, 0).unwrap_err(), AdmissionError::Bounds);
}

#[test]
fn host_r04() {
let rows: [Entry; 2] = [Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2], weight: 2u64 },Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1], weight: 1u64 }];
assert_eq!(FlatMapView::new(&rows, 0, 2).unwrap_err(), AdmissionError::MapOrder);
}

#[test]
fn host_r05() {
let bad_values_0: [Key; 12] = [[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]];
let bad_children_0: [usize; 0] = [];
let bad_nodes: [KeyNode<'_>; 1] = [KeyNode { keys: &bad_values_0, children: &bad_children_0, parent: None }];
assert_eq!(KeyTreeView::new(&bad_nodes, Some(9)).unwrap_err(), AdmissionError::Shape);
}

#[test]
fn host_r06() {
let bad_values_0: [Entry; 0] = [];
let bad_children_0: [usize; 1] = [9];
let bad_nodes: [MapNode<'_>; 1] = [MapNode { entries: &bad_values_0, children: &bad_children_0, parent: None }];
assert_eq!(TreeMapView::new(&bad_nodes, Some(0)).unwrap_err(), AdmissionError::Bounds);
}

#[test]
fn host_r07() {
let bad_values_0: [Key; 0] = [];
let bad_children_0: [usize; 1] = [1];
let bad_values_1: [Key; 1] = [[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]];
let bad_children_1: [usize; 0] = [];
let bad_nodes: [KeyNode<'_>; 2] = [KeyNode { keys: &bad_values_0, children: &bad_children_0, parent: None },KeyNode { keys: &bad_values_1, children: &bad_children_1, parent: Some(ParentLink { node: 0, edge: 1 }) }];
assert_eq!(KeyTreeView::new(&bad_nodes, Some(0)).unwrap_err(), AdmissionError::Links);
}

#[test]
fn host_r08() {
let bad_values_0: [Entry; 1] = [Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2], weight: 2u64 }];
let bad_children_0: [usize; 2] = [1,1];
let bad_values_1: [Entry; 1] = [Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1], weight: 1u64 }];
let bad_children_1: [usize; 0] = [];
let bad_nodes: [MapNode<'_>; 2] = [MapNode { entries: &bad_values_0, children: &bad_children_0, parent: None },MapNode { entries: &bad_values_1, children: &bad_children_1, parent: Some(ParentLink { node: 0, edge: 0 }) }];
assert_eq!(TreeMapView::new(&bad_nodes, Some(0)).unwrap_err(), AdmissionError::Links);
}

#[test]
fn host_r09() {
let bad_values_0: [Entry; 0] = [];
let bad_children_0: [usize; 0] = [];
let bad_values_1: [Entry; 0] = [];
let bad_children_1: [usize; 1] = [2];
let bad_values_2: [Entry; 0] = [];
let bad_children_2: [usize; 1] = [1];
let bad_nodes: [MapNode<'_>; 3] = [MapNode { entries: &bad_values_0, children: &bad_children_0, parent: None },MapNode { entries: &bad_values_1, children: &bad_children_1, parent: Some(ParentLink { node: 2, edge: 0 }) },MapNode { entries: &bad_values_2, children: &bad_children_2, parent: Some(ParentLink { node: 1, edge: 0 }) }];
assert_eq!(TreeMapView::new(&bad_nodes, Some(0)).unwrap_err(), AdmissionError::Topology);
}

#[test]
fn host_r10() {
let bad_values_0: [Key; 1] = [[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2]];
let bad_children_0: [usize; 2] = [1,2];
let bad_values_1: [Key; 1] = [[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]];
let bad_children_1: [usize; 0] = [];
let bad_values_2: [Key; 0] = [];
let bad_children_2: [usize; 1] = [3];
let bad_values_3: [Key; 1] = [[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,3]];
let bad_children_3: [usize; 0] = [];
let bad_nodes: [KeyNode<'_>; 4] = [KeyNode { keys: &bad_values_0, children: &bad_children_0, parent: None },KeyNode { keys: &bad_values_1, children: &bad_children_1, parent: Some(ParentLink { node: 0, edge: 0 }) },KeyNode { keys: &bad_values_2, children: &bad_children_2, parent: Some(ParentLink { node: 0, edge: 1 }) },KeyNode { keys: &bad_values_3, children: &bad_children_3, parent: Some(ParentLink { node: 2, edge: 0 }) }];
assert_eq!(KeyTreeView::new(&bad_nodes, Some(0)).unwrap_err(), AdmissionError::Height);
}

#[test]
fn host_r11() {
let bad_values_0: [Entry; 1] = [Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1], weight: 1u64 }];
let bad_children_0: [usize; 2] = [1,2];
let bad_values_1: [Entry; 1] = [Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2], weight: 2u64 }];
let bad_children_1: [usize; 0] = [];
let bad_values_2: [Entry; 1] = [Entry { key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,3], weight: 3u64 }];
let bad_children_2: [usize; 0] = [];
let bad_nodes: [MapNode<'_>; 3] = [MapNode { entries: &bad_values_0, children: &bad_children_0, parent: None },MapNode { entries: &bad_values_1, children: &bad_children_1, parent: Some(ParentLink { node: 0, edge: 0 }) },MapNode { entries: &bad_values_2, children: &bad_children_2, parent: Some(ParentLink { node: 0, edge: 1 }) }];
assert_eq!(TreeMapView::new(&bad_nodes, Some(0)).unwrap_err(), AdmissionError::MapOrder);
}

#[test]
fn host_r12() {
let bad_values_0: [Key; 0] = [];
let bad_children_0: [usize; 0] = [];
let bad_nodes: [KeyNode<'_>; 1] = [KeyNode { keys: &bad_values_0, children: &bad_children_0, parent: None }];
assert_eq!(KeyTreeView::new(&bad_nodes, None).unwrap_err(), AdmissionError::Links);
}
