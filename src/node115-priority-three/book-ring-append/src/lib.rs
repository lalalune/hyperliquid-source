#![no_std]
#![forbid(unsafe_code)]
//! Safe ring-slot projection for the selected node115 book append arm.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RingError {
    EmptyCapacity,
    HeadOutOfRange,
    LengthOutOfRange,
    MustGrow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AppendPlan {
    pub index: usize,
    pub next_length: usize,
}

pub fn append_slot(capacity: usize, head: usize, length: usize) -> Result<AppendPlan, RingError> {
    if capacity == 0 {
        return Err(RingError::EmptyCapacity);
    }
    if head >= capacity {
        return Err(RingError::HeadOutOfRange);
    }
    if length > capacity {
        return Err(RingError::LengthOutOfRange);
    }
    if length == capacity {
        return Err(RingError::MustGrow);
    }
    Ok(plan(capacity, head, length))
}

/// Apply the append after an opaque grow helper has supplied a larger capacity.
pub fn append_after_grow(
    grown_capacity: usize,
    head: usize,
    length: usize,
) -> Result<AppendPlan, RingError> {
    if length >= grown_capacity {
        return Err(RingError::LengthOutOfRange);
    }
    append_slot(grown_capacity, head, length)
}

fn plan(capacity: usize, head: usize, length: usize) -> AppendPlan {
    AppendPlan {
        index: if length >= capacity - head {
            length - (capacity - head)
        } else {
            head + length
        },
        next_length: length + 1,
    }
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::{AppendPlan, RingError, append_after_grow, append_slot};
    use std::vec::Vec;

    #[test]
    fn frozen_ring_vectors() {
        let text = include_str!(
            "../../../../research/work-items/RE-006-node115-book-ring-append/ring-vectors.tsv"
        );
        let mut rows = 0;
        for line in text.lines().skip(1) {
            let fields: Vec<usize> = line
                .split('\t')
                .map(|value| value.parse().unwrap())
                .collect();
            assert_eq!(
                append_slot(fields[0], fields[1], fields[2]),
                Ok(AppendPlan {
                    index: fields[3],
                    next_length: fields[4],
                }),
                "{line}"
            );
            rows += 1;
        }
        assert_eq!(rows, 1496);
    }

    #[test]
    fn large_valid_coordinates_wrap_without_overflow() {
        assert_eq!(
            append_slot(usize::MAX, usize::MAX - 2, usize::MAX - 2),
            Ok(AppendPlan {
                index: usize::MAX - 4,
                next_length: usize::MAX - 1,
            })
        );
    }

    #[test]
    fn full_ring_requires_growth_and_uses_new_capacity() {
        assert_eq!(append_slot(4, 3, 4), Err(RingError::MustGrow));
        assert_eq!(
            append_after_grow(8, 3, 4),
            Ok(AppendPlan {
                index: 7,
                next_length: 5,
            })
        );
    }

    #[test]
    fn rejects_invalid_ring_coordinates() {
        assert_eq!(append_slot(0, 0, 0), Err(RingError::EmptyCapacity));
        assert_eq!(append_slot(4, 4, 0), Err(RingError::HeadOutOfRange));
        assert_eq!(append_slot(4, 0, 5), Err(RingError::LengthOutOfRange));
        assert_eq!(append_after_grow(4, 0, 4), Err(RingError::LengthOutOfRange));
    }
}
