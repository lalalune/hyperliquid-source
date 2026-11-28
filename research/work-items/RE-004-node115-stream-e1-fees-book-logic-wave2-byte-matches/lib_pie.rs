#![forbid(unsafe_code)]
#![allow(dead_code)]

use core::panic::Location;
use e1_stubs::{InnerDiff2b0, InnerDiff2c0, OuterDiff2b8, OuterDiff2c8};

#[repr(C)]
pub struct BookOrder {
    _pad0: [u8; 0xb0],
    pub limit_px: i64,
    _pad1: [u8; 0xd2 - 0xb8],
    pub side: u8,
    _pad2: [u8; 0xe0 - 0xd3],
    pub sz: u64,
    _pad3: [u8; 8],
    pub oid: u64,
    pub user: [u8; 20],
}

#[repr(C)]
pub struct UserLevelState {
    _pad0: [u8; 0x70],
    pub total_sz: u64,
}

#[inline]
fn sat_sub_bug_assign(dst: &mut u64, b: u64) {
    match dst.checked_sub(b) {
        Some(v) => *dst = v,
        None => {
            e1_stubs::bug_log(0, Location::caller());
            *dst = 0;
        }
    }
}

#[inline]
fn sat_add_bug_assign(dst: &mut u64, b: u64) {
    match dst.checked_add(b) {
        Some(v) => *dst = v,
        None => {
            e1_stubs::bug_log(0, Location::caller());
            *dst = dst.saturating_add(b);
        }
    }
}

#[inline(always)]
fn update_total(dst: &mut u64, old_sz: u64, new_sz: u64) {
    sat_sub_bug_assign(dst, old_sz);
    sat_add_bug_assign(dst, new_sz);
}

// ============================================================================
// orderbook: Level::modify_order_sz (Perp 0x5192240 & Spot 0x5192060, 2 x 479 B)
// ============================================================================
#[inline(never)]
pub fn e1_book_modify_order_sz_perp(
    order: &mut BookOrder,
    asset: usize,
    new_sz: u64,
    diffs: &mut Vec<OuterDiff2c8>,
    level_total_sz: &mut u64,
    user_state: Option<&mut UserLevelState>,
) {
    let old_sz = order.sz;
    if new_sz == old_sz {
        return;
    }
    let side = order.side;
    order.sz = new_sz;
    let user = order.user;
    let limit_px = order.limit_px;
    let oid = order.oid;
    diffs.push(OuterDiff2c8::Inner(InnerDiff2c0::Modify {
        old_sz,
        new_sz,
        limit_px,
        asset,
        oid,
        user,
        side,
    }));
    update_total(level_total_sz, old_sz, new_sz);
    if let Some(us) = user_state {
        update_total(&mut us.total_sz, old_sz, new_sz);
    } else {
        let _ = u64::try_from(limit_px).unwrap();
    }
}

#[inline(never)]
pub fn e1_book_modify_order_sz_spot(
    order: &mut BookOrder,
    asset: usize,
    new_sz: u64,
    diffs: &mut Vec<OuterDiff2b8>,
    level_total_sz: &mut u64,
    user_state: Option<&mut UserLevelState>,
) {
    let old_sz = order.sz;
    if new_sz == old_sz {
        return;
    }
    let side = order.side;
    order.sz = new_sz;
    let user = order.user;
    let limit_px = order.limit_px;
    let oid = order.oid;
    diffs.push(OuterDiff2b8::Inner(InnerDiff2b0::Modify {
        old_sz,
        new_sz,
        limit_px,
        asset,
        oid,
        user,
        side,
    }));
    update_total(level_total_sz, old_sz, new_sz);
    if let Some(us) = user_state {
        update_total(&mut us.total_sz, old_sz, new_sz);
    } else {
        let _ = u64::try_from(limit_px).unwrap();
    }
}
