//! Safe value model of node #115's validator-epoch ring search.
//!
//! The input slice is the physical ring buffer. This API validates only the
//! supplied live view; its error types and layout are not the native ABI.
#![no_std]
#![forbid(unsafe_code)]

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Search {
    Found { logical_index: usize },
    Missing { insertion_index: usize },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvalidView {
    Bounds,
    Order,
}

/// Searches a sorted logical view of a circular buffer for an epoch.
///
/// On a hit, the first equal logical index is returned. On a miss, the index
/// before which the epoch belongs is returned. This matches the target
/// routine's `al`/`rdx` result semantics: `Found` corresponds to `al = 0`,
/// while `Missing` corresponds to `al = 1`; both carry the logical index.
///
/// `head` must name a physical slot when storage is nonempty, even when
/// `live == 0`. The live elements must be sorted in logical order. Empty
/// storage accepts only `head == 0`.
pub fn search(
    physical: &[u64],
    head: usize,
    live: usize,
    target: u64,
) -> Result<Search, InvalidView> {
    let capacity = physical.len();
    if live > capacity || (capacity == 0 && head != 0) || (capacity != 0 && head >= capacity) {
        return Err(InvalidView::Bounds);
    }

    let logical = |index: usize| {
        let tail = capacity - head;
        if index < tail {
            physical[head + index]
        } else {
            physical[index - tail]
        }
    };

    for index in 1..live {
        if logical(index - 1) > logical(index) {
            return Err(InvalidView::Order);
        }
    }

    let mut low = 0;
    let mut high = live;
    while low < high {
        let middle = low + (high - low) / 2;
        if logical(middle) < target {
            low = middle + 1;
        } else {
            high = middle;
        }
    }

    if low < live && logical(low) == target {
        Ok(Search::Found { logical_index: low })
    } else {
        Ok(Search::Missing {
            insertion_index: low,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_singleton_and_linear_boundaries() {
        assert_eq!(
            search(&[], 0, 0, 9),
            Ok(Search::Missing { insertion_index: 0 })
        );
        assert_eq!(
            search(&[10], 0, 1, 10),
            Ok(Search::Found { logical_index: 0 })
        );
        assert_eq!(
            search(&[10], 0, 1, 9),
            Ok(Search::Missing { insertion_index: 0 })
        );
        assert_eq!(
            search(&[10], 0, 1, 11),
            Ok(Search::Missing { insertion_index: 1 })
        );
        assert_eq!(
            search(&[10, 20, 30], 0, 3, 20),
            Ok(Search::Found { logical_index: 1 })
        );
        assert_eq!(
            search(&[10, 20, 30], 0, 3, 15),
            Ok(Search::Missing { insertion_index: 1 })
        );
    }

    #[test]
    fn wrapped_storage_uses_logical_indexes() {
        // Physical slot 3 is logical index 0; the unused slot is not observed.
        let ring = [20, 30, u64::MAX, 10];
        assert_eq!(
            search(&ring, 3, 3, 10),
            Ok(Search::Found { logical_index: 0 })
        );
        assert_eq!(
            search(&ring, 3, 3, 20),
            Ok(Search::Found { logical_index: 1 })
        );
        assert_eq!(
            search(&ring, 3, 3, 30),
            Ok(Search::Found { logical_index: 2 })
        );
        assert_eq!(
            search(&ring, 3, 3, 25),
            Ok(Search::Missing { insertion_index: 2 })
        );
        assert_eq!(
            search(&ring, 3, 3, 31),
            Ok(Search::Missing { insertion_index: 3 })
        );
    }

    #[test]
    fn validates_view_before_searching() {
        assert_eq!(search(&[], 1, 0, 0), Err(InvalidView::Bounds));
        assert_eq!(search(&[1, 2], 2, 0, 0), Err(InvalidView::Bounds));
        assert_eq!(search(&[1, 2], 0, 3, 0), Err(InvalidView::Bounds));
        assert_eq!(search(&[2, 1], 0, 2, 1), Err(InvalidView::Order));
    }

    #[test]
    fn spare_physical_slots_do_not_enter_the_live_order() {
        let ring = [u64::MAX, u64::MAX, 10, 20];
        assert_eq!(
            search(&ring, 2, 2, 10),
            Ok(Search::Found { logical_index: 0 })
        );
        assert_eq!(
            search(&ring, 2, 2, 20),
            Ok(Search::Found { logical_index: 1 })
        );
    }
}
