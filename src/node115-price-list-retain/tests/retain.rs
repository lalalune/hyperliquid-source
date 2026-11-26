use node115_price_list_retain::*;
use std::collections::{BTreeMap, VecDeque};

fn row(asset: u64, multiplier: i64) -> Price {
    Price { asset, multiplier }
}

#[test]
fn three_ordered_stable_passes_use_same_key_for_tree_and_wrapped_ring() {
    let mut ring = VecDeque::with_capacity(4);
    ring.extend([(0, 0), (1, 0), (2, 0), (3, 1)]);
    for _ in 0..3 {
        ring.pop_front();
    }
    ring.extend([(4, 2), (10_001, 1)]);
    assert!(!ring.as_slices().1.is_empty());
    let tree = ring.iter().copied().collect::<BTreeMap<_, _>>();
    for sizes in [Sizes::Ring(&ring), Sizes::Tree(&tree)] {
        let mut ctx = CapContext {
            sizes,
            book_totals: None,
            cap_word: 0,
        };
        let good = row(3, 2);
        let missing = row(99, i64::MAX);
        let bad = row(10_001, i64::MAX);
        let mut lists = [
            vec![good, bad, missing, good],
            vec![bad, good, bad],
            vec![bad],
        ];
        let mut messages = vec![];
        ctx.retain(&mut lists, 31, &mut messages, |_, _| {
            panic!("unexpected diagnostic")
        })
        .unwrap();
        assert_eq!(lists, [vec![good, missing, good], vec![good], vec![]]);
        assert_eq!(messages.len(), 8);
        for (pair, selector) in messages.chunks_exact(2).zip([0, 1, 1, 2]) {
            assert!(
                matches!(pair[0],Message::Cap{mapped_asset:110_001,selector:s,..} if s==selector)
            );
            assert_eq!(
                pair[1],
                Message::MissingPrice {
                    mapped_asset: 110_001,
                    selector,
                    oracle: 31
                }
            );
        }
    }
}

#[test]
fn overflow_callback_precedes_the_cap_word_observation() {
    let tree = [(10_001, i64::MAX)].into_iter().collect();
    for (before, after, expected) in [
        (0, i64::MIN, vec![Diagnostic::SumOverflow, Diagnostic::Cap]),
        (i64::MIN, 0, vec![Diagnostic::SumOverflow]),
    ] {
        let mut ctx = CapContext {
            sizes: Sizes::Tree(&tree),
            book_totals: Some(&[0, 1]),
            cap_word: before,
        };
        let mut calls = vec![];
        let mut messages = vec![];
        let mut lists = [vec![row(10_001, 1)], vec![], vec![]];
        ctx.retain(&mut lists, 1, &mut messages, |request, word| {
            calls.push(request);
            if request == Diagnostic::SumOverflow {
                *word = after
            }
        })
        .unwrap();
        assert_eq!(calls, expected);
        assert!(lists[0].is_empty());
        assert_eq!(messages.len(), 2);
    }
}

#[test]
fn stops_at_bad_book_row_preserving_processed_prefix_and_later_lists() {
    let tree = [(0, 1)].into_iter().collect();
    for (totals, error) in [
        (vec![0], Stop::BookIndex(1)),
        (vec![0, -2], Stop::NegativeBookTotal(-2)),
    ] {
        let mut ctx = CapContext {
            sizes: Sizes::Tree(&tree),
            book_totals: Some(&totals),
            cap_word: 0,
        };
        let good = row(0, 1);
        let bad = row(0, -1);
        let stop = row(10_001, 1);
        let mut lists = [vec![good, bad, stop, bad], vec![bad], vec![good]];
        let mut messages = vec![];
        assert_eq!(
            ctx.retain(&mut lists, 2, &mut messages, |_, _| {}),
            Err(error)
        );
        assert_eq!(lists, [vec![good, stop, bad], vec![bad], vec![good]]);
        assert_eq!(messages.len(), 2);
    }
}
