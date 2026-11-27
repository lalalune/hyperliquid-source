//! Order peer links and parent-child detach compaction grounded in node #115
//! (`RE-006-book-peer-links-115`: `0x58e4300`, `0x58e48e0`, `0x58e4ec0`, `0x58e5510`).

use node115_fees::UserAddress;

use crate::slab::{OrderRecord, OrderSlab, SlabIndex};

/// Trait abstracting lookup of a user's mutable order record by `(user, oid)`.
pub trait OrderRelations {
    fn find_order_mut(&mut self, user: &UserAddress, oid: u64) -> Option<&mut OrderRecord>;
}

/// Mutual peer link matching `#115` `0x58e4300` / `0x58e48e0`:
/// - Finds `first_oid` for `user`; if present sets `peer_oid = Some(second_oid)`.
/// - Regardless of whether `first_oid` was found, finds `second_oid` for `user`;
///   if present sets `peer_oid = Some(first_oid)`.
pub fn link_peers(
    store: &mut impl OrderRelations,
    user: &UserAddress,
    first_oid: u64,
    second_oid: u64,
) {
    if let Some(first) = store.find_order_mut(user, first_oid) {
        first.peer_oid = Some(second_oid);
    }
    if let Some(second) = store.find_order_mut(user, second_oid) {
        second.peer_oid = Some(first_oid);
    }
}

/// Parent detach matching `#115` `0x58e4ec0` / `0x58e5510`:
/// - Finds `oid` for `user`, unconditionally clears `parent_oid` to `None`, and returns early
///   if there was no previous parent.
/// - Otherwise finds the parent order by `(user, old_parent_oid)` and compacts `child_oids`
///   in place, removing EVERY occurrence of `oid`.
pub fn detach_from_parent(store: &mut impl OrderRelations, user: &UserAddress, oid: u64) {
    let old_parent = match store.find_order_mut(user, oid) {
        Some(order) => order.parent_oid.take(),
        None => return,
    };
    let Some(parent_oid) = old_parent else {
        return;
    };
    if let Some(parent) = store.find_order_mut(user, parent_oid) {
        parent.child_oids.retain(|&child| child != oid);
    }
}

/// Helper to look up a slab order by `(slab_index, user)` with exact 20-byte owner check.
#[inline]
pub fn find_owned_slot_mut<'a>(
    slab: &'a mut OrderSlab,
    slot: SlabIndex,
    user: &UserAddress,
) -> Option<&'a mut OrderRecord> {
    let rec = slab.get_mut(slot)?;
    if &rec.user == user { Some(rec) } else { None }
}
