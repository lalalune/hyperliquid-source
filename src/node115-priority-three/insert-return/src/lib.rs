#![no_std]
#![forbid(unsafe_code)]
//! Bounded model of node115 shared slab insert return `0x58df360`.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SlabHeader {
    pub capacity: u64,
    pub length: u64,
    pub counter: u64,
    pub head: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeadSlot {
    Vacant { next_head: u64 },
    Occupied,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InsertPlan {
    pub next: SlabHeader,
    pub returned_index: u64,
    pub grew_collection: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InsertError {
    ExpectedVacantEntry { head: u64, length: u64 },
    LengthOverflow,
}

/// Plans the measured return-side effects of the shared insert routine.
///
/// The `head_slot` argument is consulted only on the reuse arm
/// (`head < length`). On append, a caller must still provide a value, but it is
/// ignored.
pub fn plan_insert(header: SlabHeader, head_slot: HeadSlot) -> Result<InsertPlan, InsertError> {
    let counter = header.counter.saturating_add(1);

    if header.head == header.length {
        let next_index = header
            .head
            .checked_add(1)
            .ok_or(InsertError::LengthOverflow)?;
        return Ok(InsertPlan {
            next: SlabHeader {
                capacity: header.capacity,
                length: next_index,
                counter,
                head: next_index,
            },
            returned_index: header.head,
            grew_collection: header.head == header.capacity,
        });
    }

    if header.head < header.length
        && let HeadSlot::Vacant { next_head } = head_slot
    {
        return Ok(InsertPlan {
            next: SlabHeader {
                capacity: header.capacity,
                length: header.length,
                counter,
                head: next_head,
            },
            returned_index: header.head,
            grew_collection: false,
        });
    }

    Err(InsertError::ExpectedVacantEntry {
        head: header.head,
        length: header.length,
    })
}

#[cfg(test)]
mod tests {
    use super::{HeadSlot, InsertError, InsertPlan, SlabHeader, plan_insert};

    fn header(capacity: u64, length: u64, counter: u64, head: u64) -> SlabHeader {
        SlabHeader {
            capacity,
            length,
            counter,
            head,
        }
    }

    #[test]
    fn append_returns_pre_insert_length() {
        assert_eq!(
            plan_insert(header(8, 3, 10, 3), HeadSlot::Occupied),
            Ok(InsertPlan {
                next: header(8, 4, 11, 4),
                returned_index: 3,
                grew_collection: false,
            })
        );
    }

    #[test]
    fn append_at_capacity_requests_growth() {
        let plan = plan_insert(header(3, 3, 9, 3), HeadSlot::Occupied).unwrap();
        assert!(plan.grew_collection);
        assert_eq!(plan.returned_index, 3);
        assert_eq!(plan.next.length, 4);
        assert_eq!(plan.next.head, 4);
    }

    #[test]
    fn counter_saturates_before_the_decision() {
        let plan = plan_insert(header(8, 3, u64::MAX, 3), HeadSlot::Occupied).unwrap();
        assert_eq!(plan.next.counter, u64::MAX);
    }

    #[test]
    fn vacant_reuse_returns_old_head_and_installs_link() {
        assert_eq!(
            plan_insert(header(8, 5, 12, 2), HeadSlot::Vacant { next_head: 7 }),
            Ok(InsertPlan {
                next: header(8, 5, 13, 7),
                returned_index: 2,
                grew_collection: false,
            })
        );
    }

    #[test]
    fn occupied_reuse_slot_is_rejected() {
        assert_eq!(
            plan_insert(header(8, 5, 12, 2), HeadSlot::Occupied),
            Err(InsertError::ExpectedVacantEntry { head: 2, length: 5 })
        );
    }

    #[test]
    fn head_beyond_length_is_rejected() {
        assert_eq!(
            plan_insert(header(8, 5, 12, 6), HeadSlot::Vacant { next_head: 0 }),
            Err(InsertError::ExpectedVacantEntry { head: 6, length: 5 })
        );
    }

    #[test]
    fn append_index_overflow_is_rejected() {
        assert_eq!(
            plan_insert(header(u64::MAX, u64::MAX, 0, u64::MAX), HeadSlot::Occupied),
            Err(InsertError::LengthOverflow)
        );
    }
}
