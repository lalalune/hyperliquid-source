//! Sub-level priority-order queue splicing, in-place size modification with L4 diff emission,
//! and binary-grounded node #115 `Book`/`PerpDex`/`Slab` layout constants.
//!
//! Binary evidence (`RE-006-node115-priority-level-and-books`):
//! - `0x5911890` (`l1/src/book/book/impl_insert_order.rs:537:45`, `l1/src/book/level.rs:32:54`):
//!   inserts a resting order into its price level. Non-priority orders append at the level tail
//!   and initialize `level.cursor` (`first_non_priority` at `level + 0x20`) if `None`. Priority
//!   orders (`priority = Some(p)`) query `priority_orders` (`level + 0x50`) with
//!   `(Excluded(key), Unbounded)` via `0x4dce580` (`Reverse(priority)` then `oid` ascending),
//!   splicing via `0x58df360` before the first strictly-lower-priority (or later-OID equal-priority)
//!   order, or before `level.cursor` if none exists, then record the order in `priority_orders`
//!   (`0x4dbe910`) and append a 32-byte entry to `priority_ring` (`level + 0x30..0x48`).
//! - `0x58df360` (`l1/src/book/book_orders.rs:81,89`, `l1/src/slab/slab.rs:78`):
//!   `OrderSlab::insert_and_link` with `insert_before`, `0x110`-byte slab slots, and `0x2b8`-byte
//!   insert diff record emission.
//! - `0x58dfbc0` (`l1/src/book/book_orders.rs:137,145`, `l1/src/book/level.rs:32`):
//!   `OrderSlab::unlink` advancing `level.cursor` (`level + 0x20`) to `removed.next`, removing
//!   from `priority_orders` (`0x4de02d0`), and saturating-decrementing `level.total_sz`/`order_count`.
//! - `0x25da200` / `0x5192060` (`l1/src/book/level.rs:32`, `qtys/impl_sz.rs:9`, `qtys/mod.rs:831`):
//!   in-place order size modification with fast-return on `new_sz == old_sz`, `0x2c8`-byte L4 diff
//!   record emission, and `sat_sub(old_sz)` -> `sat_add(new_sz)` on both `book_total` and `level.total_sz`.
//! - `0x22e7590` & `0x276e000` (`l1/src/books.rs:14,19`, `perp_dex.rs:29`):
//!   `Book` stride `0x120` (288 B) and `PerpDex` stride `0x200` (512 B).

use std::cmp::{Ordering, Reverse};
use std::collections::{BTreeMap, Bound, VecDeque};

use node115_assets::pdi::Side;
use node115_assets::qtys::{OverflowSink, Px, Sz};
use node115_fees::UserAddress;

use crate::slab::{Level, OrderRecord, OrderSlab, SlabError, SlabIndex, UnlinkResult};

/// Verified node #115 `Book<A>` element stride in `Books` (`(idx + idx*8) << 5 = 288`, `0x22e75b9`/`0x276e05c`).
pub const BOOK_STRUCT_STRIDE_BYTES: usize = 288;

/// Verified node #115 `PerpDex` element stride in `PerpDexs` (`pdi << 9 = 512`, `0x276e03d`).
pub const PERP_DEX_STRUCT_STRIDE_BYTES: usize = 512;

/// Verified node #115 `OrderSlab` slot stride (`0x110 = 272`, `0x58df3d0`/`0x58dfbe1`).
pub const SLAB_ENTRY_STRIDE_BYTES: usize = 272;

/// Verified node #115 insert diff record size (`0x2b8 = 696`, `0x58df4df`).
pub const LEVEL_INSERT_DIFF_BYTES: usize = 696;

/// Verified node #115 modify-size diff record size (`0x2c8 = 712`, `0x25da2a7`).
pub const LEVEL_MODIFY_DIFF_BYTES: usize = 712;

/// Verified node #115 per-level priority ring entry stride (`1 << 5 = 32`, `0x5911abe`).
pub const PRIORITY_RING_ENTRY_BYTES: usize = 32;

/// Ordering key for node #115 `level.priority_orders` (`0x4dce5c7..0x4dce629`):
/// sorts primarily by **`priority` descending** (`Reverse(priority)`), breaking ties by
/// **`oid` ascending** (strict FIFO within equal priority).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PriorityKey {
    pub oid: u64,
    pub priority: u32,
}

impl Ord for PriorityKey {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        Reverse(self.priority)
            .cmp(&Reverse(other.priority))
            .then_with(|| self.oid.cmp(&other.oid))
    }
}

impl PartialOrd for PriorityKey {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Logical projection of the 32-byte ring record pushed at `0x5911a80..0x5911ad4`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PriorityRingEntry {
    pub oid: u64,
    pub priority: u32,
    pub timestamp: u64,
}

/// Logical projection of L4 book-level diff records emitted by `0x58df360` (`0x2b8` B)
/// and `0x25da200` (`0x2c8` B).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LevelDiffEvent {
    OrderInserted {
        oid: u64,
        user: UserAddress,
        side: Side,
        px: Px,
        sz: Sz,
        insert_before_oid: Option<u64>,
        timestamp: u64,
    },
    OrderSizeModified {
        oid: u64,
        user: UserAddress,
        side: Side,
        px: Px,
        old_sz: Sz,
        new_sz: Sz,
        timestamp: u64,
    },
    OrderRemoved {
        oid: u64,
        user: UserAddress,
        side: Side,
        px: Px,
        sz: Sz,
    },
}

/// Sub-level priority-aware FIFO queue matching `#115` `0x5911890`, `0x58df360`, `0x58dfbc0`,
/// and `0x25da200`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PriorityLevelQueue {
    pub level: Level,
    /// `level + 0x50`: priority orders indexed by `(Reverse(priority), oid) -> SlabIndex`.
    pub priority_orders: BTreeMap<PriorityKey, SlabIndex>,
    /// `level + 0x30..0x48`: chronological ring of priority insertions.
    pub priority_ring: VecDeque<PriorityRingEntry>,
}

impl PriorityLevelQueue {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a resting order with optional `priority`, matching `#115` `0x5911890` -> `0x58df360`.
    #[allow(clippy::too_many_arguments)]
    pub fn insert_resting(
        &mut self,
        slab: &mut OrderSlab,
        order: OrderRecord,
        priority: Option<u32>,
        timestamp: u64,
        book_total: &mut Sz,
        diffs: &mut Vec<LevelDiffEvent>,
        sink: &mut impl OverflowSink,
    ) -> Result<SlabIndex, SlabError> {
        if (order.limit_px.raw() as i64) < 0 {
            return Err(SlabError::NegativePriceKey);
        }
        let oid = order.oid;
        let user = order.user;
        let side = order.side;
        let px = order.limit_px;
        let sz = order.sz;

        match priority {
            None => {
                // Non-priority path (`0x5911998..0x59119f1`): append at tail; set cursor if None.
                let slot = slab.insert_and_link(order, &mut self.level, None, book_total, sink)?;
                if self.level.cursor.is_none() {
                    self.level.cursor = Some(slot);
                }
                diffs.push(LevelDiffEvent::OrderInserted {
                    oid,
                    user,
                    side,
                    px,
                    sz,
                    insert_before_oid: None,
                    timestamp,
                });
                Ok(slot)
            }
            Some(prio) => {
                // Priority path (`0x5911939..0x5911ad4`): find first existing priority order
                // sorting strictly after `key`, else fall back to `level.cursor` (first non-priority).
                let key = PriorityKey {
                    oid,
                    priority: prio,
                };
                let insert_before = self
                    .priority_orders
                    .range((Bound::Excluded(key), Bound::Unbounded))
                    .next()
                    .map(|(_, &slot)| slot)
                    .or(self.level.cursor);
                let insert_before_oid = insert_before.and_then(|s| slab.get(s).map(|r| r.oid));
                let slot = slab.insert_and_link(
                    order,
                    &mut self.level,
                    insert_before,
                    book_total,
                    sink,
                )?;
                self.priority_orders.insert(key, slot);
                self.priority_ring.push_back(PriorityRingEntry {
                    oid,
                    priority: prio,
                    timestamp,
                });
                diffs.push(LevelDiffEvent::OrderInserted {
                    oid,
                    user,
                    side,
                    px,
                    sz,
                    insert_before_oid,
                    timestamp,
                });
                Ok(slot)
            }
        }
    }

    /// Modify a resting order's size in place, matching `#115` `0x25da200` (`l1/src/book/level.rs:32`).
    ///
    /// Returns `Ok(false)` on fast no-op (`new_sz == old_sz`), `Ok(true)` after emitting an
    /// `OrderSizeModified` diff and updating both `book_total` and `level.total_sz` via
    /// `sat_sub(old_sz)` -> `sat_add(new_sz)`.
    #[allow(clippy::too_many_arguments)]
    pub fn modify_order_sz(
        &mut self,
        slab: &mut OrderSlab,
        slot: SlabIndex,
        new_sz: Sz,
        timestamp: u64,
        book_total: &mut Sz,
        diffs: &mut Vec<LevelDiffEvent>,
        sink: &mut impl OverflowSink,
    ) -> Result<bool, SlabError> {
        let Some(rec) = slab.get_mut(slot) else {
            return Ok(false);
        };
        let old_sz = rec.sz;
        if new_sz == old_sz {
            return Ok(false);
        }
        if (rec.limit_px.raw() as i64) < 0 {
            return Err(SlabError::NegativePriceKey);
        }
        rec.sz = new_sz;
        let oid = rec.oid;
        let user = rec.user;
        let side = rec.side;
        let px = rec.limit_px;

        diffs.push(LevelDiffEvent::OrderSizeModified {
            oid,
            user,
            side,
            px,
            old_sz,
            new_sz,
            timestamp,
        });

        // Exact `#115` `0x25da2cb..0x25da395`: subtract old_sz then add new_sz with overflow sink.
        *book_total = book_total.sat_sub(old_sz, sink).sat_add(new_sz, sink);
        self.level.total_sz = self
            .level
            .total_sz
            .sat_sub(old_sz, sink)
            .sat_add(new_sz, sink);
        Ok(true)
    }

    /// Remove `slot` from the slab, level doubly-linked list, and `priority_orders` map
    /// (when `priority = Some(p)`), matching `#115` `0x58dfbc0`.
    pub fn remove_order(
        &mut self,
        slab: &mut OrderSlab,
        slot: SlabIndex,
        priority: Option<u32>,
        book_total: &mut Sz,
        diffs: &mut Vec<LevelDiffEvent>,
        sink: &mut impl OverflowSink,
    ) -> Result<Option<UnlinkResult>, SlabError> {
        let Some(res) = slab.unlink(slot, Some(&mut self.level), book_total, sink)? else {
            return Ok(None);
        };
        if let Some(prio) = priority {
            self.priority_orders.remove(&PriorityKey {
                oid: res.removed.oid,
                priority: prio,
            });
        }
        diffs.push(LevelDiffEvent::OrderRemoved {
            oid: res.removed.oid,
            user: res.removed.user,
            side: res.removed.side,
            px: res.removed.limit_px,
            sz: res.removed.sz,
        });
        Ok(Some(res))
    }
}
