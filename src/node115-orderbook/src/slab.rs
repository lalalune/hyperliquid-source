//! Order slab and per-level doubly-linked FIFO queue grounded in node #115
//! (`RE-006-book-slab-link-115`: `0x23cd2d0`, `0x23cd700`, `0x58df360`, `0x58df790`,
//! `0x58dfbc0`, `0x58dff20`; `l1/src/slab/slab.rs:78`, `l1/src/book/book_orders.rs:81,89,137,145`,
//! `l1/src/book/level.rs:32`).

use node115_assets::pdi::Side;
use node115_assets::qtys::{OverflowKind, OverflowSink, Px, Sz};
use node115_fees::UserAddress;

/// Stable slab slot index for a resting order.
pub type SlabIndex = usize;

/// Resting order record stored inside `OrderSlab` (logical projection of the `0x110`-byte
/// `#115` slab entry, with explicit prev/next doubly-linked list links and order fields).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrderRecord {
    pub oid: u64,
    pub user: UserAddress,
    pub side: Side,
    pub limit_px: Px,
    pub sz: Sz,
    pub orig_sz: Sz,
    pub reduce_only: bool,
    pub timestamp: u64,
    pub cloid: Option<[u8; 16]>,
    pub prev: Option<SlabIndex>,
    pub next: Option<SlabIndex>,
    /// Peer link (`+0x20/+0x28` in `RE-006-book-peer-links-115`).
    pub peer_oid: Option<u64>,
    /// Parent link (`+0x10/+0x18` in `RE-006-book-peer-links-115`).
    pub parent_oid: Option<u64>,
    /// Child OID list (`+0x38/+0x40` in `RE-006-book-peer-links-115`).
    pub child_oids: Vec<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum SlabEntry {
    Vacant { next_free: usize },
    Occupied(OrderRecord),
}

/// Errors corresponding to `#115` slab/link corruption panics (`slab.rs:78`, `book_orders.rs:81/89/137/145`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlabError {
    CorruptFreeIndex(usize),
    MissingNeighbour(SlabIndex),
    NegativePriceKey,
}

/// Per-price-level doubly-linked FIFO queue (`l1/src/book/level.rs`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Level {
    pub head: Option<SlabIndex>,
    pub tail: Option<SlabIndex>,
    /// Cached iteration cursor (`level + 0x20 / +0x28` in `RE-006-book-slab-link-115`).
    pub cursor: Option<SlabIndex>,
    /// Aggregate resting size (`level + 0x70`, saturating add/sub).
    pub total_sz: Sz,
    /// Aggregate resting order count (`level + 0x78`, saturating add/sub).
    pub order_count: u64,
}

impl Level {
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.head.is_none() && self.tail.is_none()
    }
}

/// Outcome of `OrderSlab::unlink` matching `RE-006-book-slab-link-115` (`0x58dfbc0` / `0x58dff20`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnlinkResult {
    pub removed: OrderRecord,
    pub level_emptied: bool,
}

/// Free-list slab storing resting orders (`l1/src/slab/slab.rs`).
#[derive(Clone, Debug, Default)]
pub struct OrderSlab {
    entries: Vec<SlabEntry>,
    live_count: usize,
    next_free: usize,
}

impl OrderSlab {
    pub fn new() -> Self {
        Self::default()
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.live_count
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.live_count == 0
    }

    #[inline]
    pub fn slot_len(&self) -> usize {
        self.entries.len()
    }

    #[inline]
    pub fn get(&self, idx: SlabIndex) -> Option<&OrderRecord> {
        match self.entries.get(idx)? {
            SlabEntry::Occupied(rec) => Some(rec),
            SlabEntry::Vacant { .. } => None,
        }
    }

    #[inline]
    pub fn get_mut(&mut self, idx: SlabIndex) -> Option<&mut OrderRecord> {
        match self.entries.get_mut(idx)? {
            SlabEntry::Occupied(rec) => Some(rec),
            SlabEntry::Vacant { .. } => None,
        }
    }

    /// Insert `order` into the slab (reusing `next_free` or pushing at the end, matching
    /// `slab.rs:78`) and link it into `level` either before `insert_before` (when `Some(slot)`
    /// points to an occupied slot) or at the level tail, updating `caller_total` and `level`
    /// with saturating arithmetic (`RE-006-book-slab-link-115`).
    pub fn insert_and_link(
        &mut self,
        mut order: OrderRecord,
        level: &mut Level,
        insert_before: Option<SlabIndex>,
        caller_total: &mut Sz,
        sink: &mut impl OverflowSink,
    ) -> Result<SlabIndex, SlabError> {
        let size = order.sz;
        *caller_total = caller_total.sat_add(size, sink);

        // Determine linkage target: valid occupied `insert_before` -> link before it; else append at tail.
        let before_slot = insert_before.filter(|&slot| self.get(slot).is_some());
        let (prev_idx, next_idx) = if let Some(target) = before_slot {
            let old_prev = self.get(target).unwrap().prev;
            (old_prev, Some(target))
        } else {
            (level.tail, None)
        };
        order.prev = prev_idx;
        order.next = next_idx;

        // Allocate slab slot (`slab.rs:78`).
        let new_idx = self.next_free;
        if new_idx == self.entries.len() {
            self.entries.push(SlabEntry::Occupied(order));
            self.next_free = self.entries.len();
        } else if new_idx < self.entries.len() {
            let next_free = match self.entries[new_idx] {
                SlabEntry::Vacant { next_free } => next_free,
                SlabEntry::Occupied(_) => return Err(SlabError::CorruptFreeIndex(new_idx)),
            };
            self.entries[new_idx] = SlabEntry::Occupied(order);
            self.next_free = next_free;
        } else {
            return Err(SlabError::CorruptFreeIndex(new_idx));
        }
        self.live_count = self.live_count.saturating_add(1);

        // Patch neighbours (`book_orders.rs:81` & `book_orders.rs:89`).
        if let Some(next_slot) = next_idx {
            let next_rec = self
                .get_mut(next_slot)
                .ok_or(SlabError::MissingNeighbour(next_slot))?;
            next_rec.prev = Some(new_idx);
        } else {
            level.tail = Some(new_idx);
        }

        if let Some(prev_slot) = prev_idx {
            let prev_rec = self
                .get_mut(prev_slot)
                .ok_or(SlabError::MissingNeighbour(prev_slot))?;
            prev_rec.next = Some(new_idx);
        } else {
            level.head = Some(new_idx);
        }

        level.total_sz = level.total_sz.sat_add(size, sink);
        level.order_count = level.order_count.saturating_add(1);
        Ok(new_idx)
    }

    /// Remove `slot` from the slab and unlink it from `level` (when `Some`), matching
    /// `RE-006-book-slab-link-115` (`0x58dfbc0` / `0x58dff20`):
    /// - Absent or vacant slot returns `Ok(None)` without mutating anything.
    /// - Advances `level.cursor` to `removed.next` when `level.cursor == Some(slot)`.
    /// - Clamps `level.total_sz` down to `0` without calling the overflow hook (exact `#115`
    ///   observation), while `caller_total` uses `sat_sub` (reporting underflow through `sink`).
    pub fn unlink(
        &mut self,
        slot: SlabIndex,
        level: Option<&mut Level>,
        caller_total: &mut Sz,
        sink: &mut impl OverflowSink,
    ) -> Result<Option<UnlinkResult>, SlabError> {
        if self.get(slot).is_none() {
            return Ok(None);
        }
        let prev_free = self.next_free;
        let entry = std::mem::replace(
            &mut self.entries[slot],
            SlabEntry::Vacant {
                next_free: prev_free,
            },
        );
        let removed = match entry {
            SlabEntry::Occupied(rec) => rec,
            SlabEntry::Vacant { .. } => unreachable!(),
        };
        self.live_count = self.live_count.saturating_sub(1);
        self.next_free = slot;

        *caller_total = caller_total.sat_sub(removed.sz, sink);

        let level_emptied = if let Some(lvl) = level {
            // `level.rs:32` guard: sign bit on raw price key must be clear.
            if (removed.limit_px.raw() as i64) < 0 {
                return Err(SlabError::NegativePriceKey);
            }
            if lvl.cursor == Some(slot) {
                lvl.cursor = removed.next;
            }
            lvl.total_sz = Sz(lvl.total_sz.raw().saturating_sub(removed.sz.raw()));
            lvl.order_count = lvl.order_count.saturating_sub(1);

            match removed.prev {
                Some(prev_slot) => {
                    let prev_rec = self
                        .get_mut(prev_slot)
                        .ok_or(SlabError::MissingNeighbour(prev_slot))?;
                    prev_rec.next = removed.next;
                }
                None => {
                    lvl.head = removed.next;
                }
            }
            match removed.next {
                Some(next_slot) => {
                    let next_rec = self
                        .get_mut(next_slot)
                        .ok_or(SlabError::MissingNeighbour(next_slot))?;
                    next_rec.prev = removed.prev;
                }
                None => {
                    lvl.tail = removed.prev;
                }
            }
            lvl.is_empty()
        } else {
            false
        };

        Ok(Some(UnlinkResult {
            removed,
            level_emptied,
        }))
    }

    /// Reduce the remaining size of an occupied order in place, updating both `level.total_sz`
    /// and `caller_total` with `#115` saturating subtraction.
    pub fn reduce_order_sz(
        &mut self,
        slot: SlabIndex,
        fill_sz: Sz,
        level: &mut Level,
        caller_total: &mut Sz,
        sink: &mut impl OverflowSink,
    ) -> Option<Sz> {
        let rec = self.get_mut(slot)?;
        let (new_sz, borrow) = rec.sz.raw().overflowing_sub(fill_sz.raw());
        if borrow {
            sink.report(OverflowKind::UnsignedSub);
            rec.sz = Sz::ZERO;
        } else {
            rec.sz = Sz(new_sz);
        }
        level.total_sz = Sz(level.total_sz.raw().saturating_sub(fill_sz.raw()));
        *caller_total = caller_total.sat_sub(fill_sz, sink);
        Some(rec.sz)
    }

    /// Collect all order slots in a level in FIFO (head -> tail) order.
    pub fn level_slots(&self, level: &Level) -> Vec<SlabIndex> {
        self.iter_level_slots(level).collect()
    }

    /// Visit FIFO links on demand with the same bound as the collected view.
    pub(crate) fn iter_level_slots(&self, level: &Level) -> impl Iterator<Item = SlabIndex> {
        std::iter::successors(level.head, |&idx| self.get(idx).and_then(|order| order.next))
            .take(self.entries.len().saturating_add(1))
    }
}
