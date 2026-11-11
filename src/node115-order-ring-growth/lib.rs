//! Successful full 32-byte ring growth in node #115 at 0x455df30.
//! The caller supplies initialized opaque rows. Padding interpretation, allocator
//! identity and insertion policy are deliberately outside this contract.
#![no_std]
extern crate alloc;
use alloc::vec::Vec;

pub type Row = [u8; 32];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidHead,
    CapacityOverflow,
    Allocation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Movement {
    None,
    Prefix {
        rows: u64,
        destination: u64,
    },
    Suffix {
        source: u64,
        rows: u64,
        destination: u64,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Plan {
    pub capacity: u64,
    pub head: u64,
    pub movement: Movement,
}

/// Native full-ring callers test length == capacity before entering the helper.
/// The byte bound is 2^63 - alignment, with alignment 8, from 0x43bd550.
pub fn plan_full(capacity: u64, head: u64) -> Result<Plan, Error> {
    if (capacity == 0 && head != 0) || (capacity != 0 && head >= capacity) {
        return Err(Error::InvalidHead);
    }
    let new_capacity = capacity
        .checked_mul(2)
        .ok_or(Error::CapacityOverflow)?
        .max(4);
    if new_capacity
        .checked_mul(32)
        .is_none_or(|bytes| bytes > (1u64 << 63) - 8)
    {
        return Err(Error::CapacityOverflow);
    }
    let (new_head, movement) = if head == 0 {
        (0, Movement::None)
    } else {
        let suffix = capacity - head;
        let prefix = head; // length == old capacity
        if suffix <= prefix || new_capacity - capacity < prefix {
            let destination = new_capacity - suffix;
            (
                destination,
                Movement::Suffix {
                    source: head,
                    rows: suffix,
                    destination,
                },
            )
        } else {
            (
                head,
                Movement::Prefix {
                    rows: prefix,
                    destination: capacity,
                },
            )
        }
    };
    Ok(Plan {
        capacity: new_capacity,
        head: new_head,
        movement,
    })
}

/// Grow actual owned row storage and retain its logical sequence. Extra storage
/// is zero initialized by this implementation; native unused bytes are not read
/// or claimed to be zero. The returned length remains the old backing length.
pub fn grow_full(backing: &mut Vec<Row>, head: &mut usize) -> Result<(), Error> {
    let p = plan_full(backing.len() as u64, *head as u64)?;
    let new_capacity = usize::try_from(p.capacity).map_err(|_| Error::CapacityOverflow)?;
    backing
        .try_reserve_exact(new_capacity - backing.len())
        .map_err(|_| Error::Allocation)?;
    backing.resize(new_capacity, [0; 32]);
    match p.movement {
        Movement::None => (),
        Movement::Prefix { rows, destination } => {
            backing.copy_within(0..rows as usize, destination as usize)
        }
        Movement::Suffix {
            source,
            rows,
            destination,
        } => backing.copy_within(
            source as usize..(source + rows) as usize,
            destination as usize,
        ),
    }
    *head = p.head as usize;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn row(i: usize) -> Row {
        core::array::from_fn(|j| ((i * 73 + j * 19) & 255) as u8)
    }

    #[test]
    fn all_full_small_rings_preserve_whole_rows() {
        // Independent queue oracle: rotate before growth, compare after growth.
        for capacity in 1..=128 {
            for initial_head in 0..capacity {
                let mut storage: Vec<_> = (0..capacity).map(row).collect();
                let mut expected = storage.clone();
                expected.rotate_left(initial_head);
                let mut head = initial_head;
                grow_full(&mut storage, &mut head).unwrap();
                let observed: Vec<_> = (0..capacity)
                    .map(|i| storage[(head + i) % storage.len()])
                    .collect();
                assert_eq!(
                    observed, expected,
                    "capacity={capacity}, head={initial_head}"
                );
                assert_eq!(storage.len(), (capacity * 2).max(4));
            }
        }
    }

    #[test]
    fn empty_and_contiguous() {
        let mut storage = vec![];
        let mut head = 0;
        grow_full(&mut storage, &mut head).unwrap();
        assert_eq!(storage.len(), 4);
        assert_eq!(head, 0);
        assert_eq!(plan_full(4, 0).unwrap().movement, Movement::None);
    }

    #[test]
    fn smaller_segment_and_tie_choose_native_side() {
        assert_eq!(
            plan_full(8, 2).unwrap(),
            Plan {
                capacity: 16,
                head: 2,
                movement: Movement::Prefix {
                    rows: 2,
                    destination: 8
                }
            }
        );
        assert_eq!(
            plan_full(8, 4).unwrap(),
            Plan {
                capacity: 16,
                head: 12,
                movement: Movement::Suffix {
                    source: 4,
                    rows: 4,
                    destination: 12
                }
            }
        );
        assert_eq!(plan_full(8, 7).unwrap().head, 15);
    }

    #[test]
    fn target_allocation_bound() {
        let largest_old_capacity = (((1u64 << 63) - 8) / 32) / 2;
        assert!(plan_full(largest_old_capacity, 0).is_ok());
        assert_eq!(
            plan_full(largest_old_capacity + 1, 0),
            Err(Error::CapacityOverflow)
        );
        assert_eq!(plan_full(u64::MAX, 0), Err(Error::CapacityOverflow));
        assert_eq!(plan_full(0, 1), Err(Error::InvalidHead));
        assert_eq!(plan_full(5, 5), Err(Error::InvalidHead));
    }

    #[test]
    fn appending_after_growth_preserves_saved_word_and_neighbors() {
        let mut rows: Vec<_> = (0..4).map(row).collect();
        let mut head = 3;
        let old_len = rows.len();
        let expected = [rows[3], rows[0], rows[1], rows[2]];
        grow_full(&mut rows, &mut head).unwrap();
        let mut incoming = row(999);
        incoming[..8].copy_from_slice(&0xfedcba9876543210u64.to_le_bytes());
        let index = (head + old_len) % rows.len();
        rows[index] = incoming;
        for (i, expected_row) in expected.iter().enumerate() {
            assert_eq!(&rows[(head + i) % rows.len()], expected_row);
        }
        assert_eq!(&rows[index][..8], &0xfedcba9876543210u64.to_le_bytes());
    }
}
