//! Order book matching engine, TIF dispatch, self-trade prevention, resting reduce-only
//! checks, and OID cancel/modify grounded in node #115 (`RE-006-node115-match-tif-cancel`).
//!
//! Binary anchors:
//! - Crossing predicate: `0x5902560..0x5902581` (`would_cross`).
//! - TIF jump table `.rodata` `0x936ecc`:
//!   `Alo` (0 -> `0x59025c6`, rejects crossing with `0x8000_0000_0000_0006` + BBO),
//!   `Ioc`/`FrontendMarket`/`LiquidationMarket` (1/3/4 -> `0x59025b0`, rejects non-crossing with `0x8000_0000_0000_0008`),
//!   `Gtc` (2 -> `0x590261a`).
//! - Upper cap constant: `0x590264b` (`0x38d7ea4c68000` = `10^15`).
//! - Match step (`0x5911dd0`): 20-byte SIMD self-trade guard + 8-address HLP vault mutual
//!   self-trade guard (`0x421a520`), resting `reduce_only` (`+0xc0`) polarity & size clamp,
//!   maker then taker `max_trade_sz` margin checks.
//! - Cancel order lookup (`0x23ce3e0`): OID hash `oid.wrapping_mul(0xf1357aea2e62a9c5).rotate_left(20)`,
//!   slab bounds & vacant check, 20-byte SIMD owner check.

use std::collections::{BTreeMap, HashMap};

use node115_assets::pdi::Side;
use node115_assets::qtys::{OverflowSink, Px, Sz, Szi};
use node115_fees::UserAddress;
use node115_fees::vlm::{
    OpenOrderDecision, OpenOrderDescriptor, UserVolumeTotals, check_open_order_cap,
    is_privileged_open_order_address,
};
use node115_tif_name_codec::Tif;

use crate::relations::OrderRelations;
use crate::slab::{Level, OrderRecord, OrderSlab, SlabError, SlabIndex};

/// `#115` raw result head for post-only (`Alo`) crossing rejection (`0x5902611`).
pub const BAD_ALO_HEAD: u64 = 0x8000_0000_0000_0006;

/// `#115` raw result head for non-crossing `Ioc`/`FrontendMarket`/`LiquidationMarket` (`0x59025bd`).
pub const IOC_CANCEL_HEAD: u64 = 0x8000_0000_0000_0008;

/// `#115` upper cap constant observed at `0x590264b` (`0x38d7ea4c68000` = `10^15`).
pub const MAX_ORDER_CAP: u64 = 1_000_000_000_000_000;

/// Exact `#115` OID hash observed in cancel lookup `0x23ce47a` (`imul 0xf1357aea2e62a9c5; rol 20`).
#[inline]
pub const fn cancel_oid_hash(oid: u64) -> u64 {
    oid.wrapping_mul(0xf135_7aea_2e62_a9c5).rotate_left(20)
}

/// Exact `#115` crossing predicate observed at `0x5902560..0x5902581`:
/// - `Bid` (0): crosses when `best_opposite_px <= limit_px`
/// - `Ask` (1): crosses when `best_opposite_px >= limit_px`
#[inline]
pub const fn would_cross(side: Side, limit_px: Px, best_opposite_px: Option<Px>) -> bool {
    let Some(best) = best_opposite_px else {
        return false;
    };
    match side {
        Side::Bid => best.raw() <= limit_px.raw(),
        Side::Ask => best.raw() >= limit_px.raw(),
    }
}

/// Risk / position oracle queried by the `#115` match step (`0x5911dd0`).
pub trait BookRiskOracle {
    /// Returns the user's current signed position (`*0x64e4e80` in `0x5911f6e`).
    fn signed_position(&self, user: &UserAddress) -> Szi;

    /// Returns the maximum fillable size allowed by margin for `(user, side, px)` (`*0x64e5b20`).
    fn max_trade_sz(&self, user: &UserAddress, side: Side, px: Px, requested: Sz) -> Sz;

    /// Optional hook to update position after a trade executes.
    fn on_fill(&mut self, _taker: &UserAddress, _maker: &UserAddress, _taker_side: Side, _px: Px, _sz: Sz) {}
}

/// Default permissive risk oracle for standalone book tests (infinite margin, zero initial position).
#[derive(Clone, Debug, Default)]
pub struct UnboundedRiskOracle {
    pub positions: HashMap<UserAddress, Szi>,
}

impl BookRiskOracle for UnboundedRiskOracle {
    fn signed_position(&self, user: &UserAddress) -> Szi {
        self.positions.get(user).copied().unwrap_or(Szi::ZERO)
    }

    fn max_trade_sz(&self, _user: &UserAddress, _side: Side, _px: Px, requested: Sz) -> Sz {
        requested
    }

    fn on_fill(&mut self, taker: &UserAddress, maker: &UserAddress, taker_side: Side, _px: Px, sz: Sz) {
        let delta = sz.raw() as i64;
        let taker_delta = match taker_side {
            Side::Bid => delta,
            Side::Ask => -delta,
        };
        let t = self.positions.entry(*taker).or_insert(Szi::ZERO);
        t.0 = t.0.saturating_add(taker_delta);
        let m = self.positions.entry(*maker).or_insert(Szi::ZERO);
        m.0 = m.0.saturating_sub(taker_delta);
    }
}

/// Reason a resting order was cancelled during matching (status tags `0`, `1`, `2` in `0x5911dd0`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestingCancelReason {
    /// Tag `0`: maker `max_trade_sz` clamped the fill (`0x59120d8`).
    InsufficientMargin,
    /// Tag `1`: resting `reduce_only` order had no matching position or exceeded `abs(szi)` (`0x5911f93` / `0x5911fe2`).
    ReduceOnly,
    /// Tag `2`: self-trade (`taker == maker` or both in 8-address HLP vault set `0x421a520`, `0x5911eda`).
    SelfTrade,
}

/// One executed trade fill produced by `Book::insert_order`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FillEvent {
    pub taker: UserAddress,
    pub maker: UserAddress,
    pub taker_oid: u64,
    pub maker_oid: u64,
    pub taker_side: Side,
    pub px: Px,
    pub sz: Sz,
}

/// Aggregated L2 price level snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct L2Level {
    pub px: Px,
    pub sz: Sz,
    pub n_orders: u64,
}

/// Order placement request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InsertOrderRequest {
    pub oid: u64,
    pub user: UserAddress,
    pub side: Side,
    pub limit_px: Px,
    pub sz: Sz,
    pub tif: Tif,
    pub reduce_only: bool,
    pub timestamp: u64,
    pub cloid: Option<[u8; 16]>,
}

/// Rejection reasons returned by `Book::insert_order`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InsertError {
    ZeroSize,
    ZeroPrice,
    ExceedsMaxCap,
    DuplicateOid(u64),
    BadAloPx { bbo: (Option<Px>, Option<Px>) },
    IocCancel,
    TooManyOpenOrders,
    Slab(SlabError),
}

/// Final resting/fill status of an accepted order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OrderStatus {
    Filled,
    Resting { oid: u64, remaining: Sz },
    IocRemainderCancelled { filled: Sz, cancelled: Sz },
}

/// Full outcome of `Book::insert_order`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InsertOutcome {
    pub status: OrderStatus,
    pub fills: Vec<FillEvent>,
    pub cancelled_resting: Vec<(u64, RestingCancelReason)>,
}

/// Errors returned by `Book::cancel_order`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CancelError {
    NotFound,
    WrongOwner,
    Slab(SlabError),
}

/// Request to modify an existing resting order (cancel + re-insert preserving user & new params).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModifyOrderRequest {
    pub old_oid: u64,
    pub new_oid: u64,
    pub user: UserAddress,
    pub new_side: Side,
    pub new_limit_px: Px,
    pub new_sz: Sz,
    pub new_tif: Tif,
    pub new_reduce_only: bool,
    pub timestamp: u64,
    pub new_cloid: Option<[u8; 16]>,
}

/// Errors returned by `Book::modify_order`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModifyError {
    Cancel(CancelError),
    Insert(InsertError),
}

/// Single-asset central limit order book (`l1/src/book/book/mod.rs`).
///
/// Uses `#115`'s signed price key convention (`Side::signed_price_key`):
/// - `bids` keyed by `-(px as i64)` so `BTreeMap` ascending iteration yields highest bid first!
/// - `asks` keyed by `+(px as i64)` so `BTreeMap` ascending iteration yields lowest ask first!
#[derive(Clone, Debug, Default)]
pub struct Book {
    slab: OrderSlab,
    bids: BTreeMap<i64, Level>,
    asks: BTreeMap<i64, Level>,
    oid_to_slot: HashMap<u64, SlabIndex>,
    user_open_counts: HashMap<UserAddress, u64>,
    total_book_sz: Sz,
}

impl Book {
    pub fn new() -> Self {
        Self::default()
    }

    #[inline]
    pub fn total_sz(&self) -> Sz {
        self.total_book_sz
    }

    #[inline]
    pub fn open_order_count(&self, user: &UserAddress) -> u64 {
        self.user_open_counts.get(user).copied().unwrap_or(0)
    }

    #[inline]
    pub fn total_open_orders(&self) -> usize {
        self.slab.len()
    }

    /// Lookup resting order by OID.
    #[inline]
    pub fn get_order(&self, oid: u64) -> Option<&OrderRecord> {
        let &slot = self.oid_to_slot.get(&oid)?;
        self.slab.get(slot)
    }

    #[inline]
    fn half(&self, side: Side) -> &BTreeMap<i64, Level> {
        match side {
            Side::Bid => &self.bids,
            Side::Ask => &self.asks,
        }
    }

    #[inline]
    fn half_mut(&mut self, side: Side) -> &mut BTreeMap<i64, Level> {
        match side {
            Side::Bid => &mut self.bids,
            Side::Ask => &mut self.asks,
        }
    }

    /// Best price on `side` (`highest bid` or `lowest ask`).
    pub fn best_px(&self, side: Side) -> Option<Px> {
        let (&signed_key, _) = self.half(side).iter().next()?;
        Some(Px(signed_key.unsigned_abs()))
    }

    /// Best bid and best ask (`(best_bid, best_ask)`).
    pub fn bbo(&self) -> (Option<Px>, Option<Px>) {
        (self.best_px(Side::Bid), self.best_px(Side::Ask))
    }

    /// Midpoint price `(best_bid + best_ask) / 2` when both sides are populated.
    pub fn mid_px(&self) -> Option<Px> {
        let (Some(b), Some(a)) = self.bbo() else {
            return None;
        };
        Some(Px(b.raw() / 2 + a.raw() / 2 + ((b.raw() & 1) & (a.raw() & 1))))
    }

    /// Snapshot up to `depth` aggregated L2 levels on `side` in price-priority order.
    pub fn l2_levels(&self, side: Side, depth: usize) -> Vec<L2Level> {
        self.half(side)
            .iter()
            .take(depth)
            .map(|(&key, lvl)| L2Level {
                px: Px(key.unsigned_abs()),
                sz: lvl.total_sz,
                n_orders: lvl.order_count,
            })
            .collect()
    }

    /// Checks whether `user` passes the `#115` open-order cap (`0x5495210`/`0x5495680`).
    pub fn check_user_open_order_cap(
        &self,
        user: &UserAddress,
        descriptor: OpenOrderDescriptor,
        perp_dex_volumes: &[UserVolumeTotals],
        spot_volume: UserVolumeTotals,
        sink: &mut impl OverflowSink,
    ) -> OpenOrderDecision {
        check_open_order_cap(
            user,
            self.open_order_count(user),
            descriptor,
            perp_dex_volumes,
            spot_volume,
            sink,
        )
    }

    /// Insert an order following the exact `#115` `impl_insert_order.rs` (`0x5901dd0` + `0x5911dd0`)
    /// crossing, TIF, self-trade prevention, resting reduce-only, margin clamping, and FIFO
    /// resting rules.
    pub fn insert_order(
        &mut self,
        req: InsertOrderRequest,
        risk: &mut impl BookRiskOracle,
        sink: &mut impl OverflowSink,
    ) -> Result<InsertOutcome, InsertError> {
        if req.sz.is_zero() {
            return Err(InsertError::ZeroSize);
        }
        if req.limit_px.raw() == 0 {
            return Err(InsertError::ZeroPrice);
        }
        if req.limit_px.raw() > MAX_ORDER_CAP || req.sz.raw() > MAX_ORDER_CAP {
            return Err(InsertError::ExceedsMaxCap);
        }
        if self.oid_to_slot.contains_key(&req.oid) {
            return Err(InsertError::DuplicateOid(req.oid));
        }

        let opp_side = req.side.opposite();
        let crosses = would_cross(req.side, req.limit_px, self.best_px(opp_side));

        // Exact `.rodata` `0x936ecc` TIF jump table behavior:
        let is_ioc = match req.tif {
            Tif::Alo => {
                if crosses {
                    return Err(InsertError::BadAloPx { bbo: self.bbo() });
                }
                false
            }
            Tif::Ioc | Tif::FrontendMarket | Tif::LiquidationMarket => {
                if !crosses {
                    return Err(InsertError::IocCancel);
                }
                true
            }
            Tif::Gtc => false,
        };

        let mut remaining = req.sz;
        let mut fills = Vec::new();
        let mut cancelled_resting = Vec::new();

        // Match against opposite side in strict price-time priority (`0x5911dd0`).
        while !remaining.is_zero() {
            let Some((&best_key, _)) = self.half(opp_side).iter().next() else {
                break;
            };
            let best_px = Px(best_key.unsigned_abs());
            if !would_cross(req.side, req.limit_px, Some(best_px)) {
                break;
            }
            let Some(head_slot) = self.half(opp_side).get(&best_key).and_then(|l| l.head) else {
                self.half_mut(opp_side).remove(&best_key);
                continue;
            };
            let resting = self.slab.get(head_slot).expect("head slot occupied").clone();

            // 1. Self-trade prevention (`0x5911e73` identical user OR `0x5911eb8` mutual HLP vault).
            let self_trade = resting.user == req.user
                || (is_privileged_open_order_address(&req.user)
                    && is_privileged_open_order_address(&resting.user));
            if self_trade {
                self.unlink_resting_slot(opp_side, best_key, head_slot, &resting, sink)
                    .map_err(InsertError::Slab)?;
                cancelled_resting.push((resting.oid, RestingCancelReason::SelfTrade));
                continue;
            }

            // 2. Resting `reduce_only` check (`0x5911f30..0x5911ffa`).
            let mut cancel_resting_after: Option<RestingCancelReason> = None;
            let avail_resting = if resting.reduce_only {
                let pos = risk.signed_position(&resting.user);
                // `#115` `0x5911f74..0x5911f83`:
                // `szi == 0 || ((szi <= 0) ^ taker_side_byte)` rejects resting reduce-only order.
                // Verify polarity:
                // - taker Bid (0) hits resting Ask (selling): resting must be LONG (`szi > 0`),
                //   so `szi <= 0` => `(true ^ false) = true` -> cancel!
                // - taker Ask (1) hits resting Bid (buying): resting must be SHORT (`szi < 0`),
                //   so `szi > 0` => `(false ^ true) = true` -> cancel!
                let wrong_polarity = pos.raw() == 0 || ((pos.raw() <= 0) ^ (req.side.as_u8() != 0));
                if wrong_polarity {
                    self.unlink_resting_slot(opp_side, best_key, head_slot, &resting, sink)
                        .map_err(InsertError::Slab)?;
                    cancelled_resting.push((resting.oid, RestingCancelReason::ReduceOnly));
                    continue;
                }
                let abs_pos = pos.abs_sz();
                let clamped = Sz(resting.sz.raw().min(abs_pos.raw()));
                if clamped < remaining && abs_pos < resting.sz {
                    cancel_resting_after = Some(RestingCancelReason::ReduceOnly);
                }
                clamped
            } else {
                resting.sz
            };

            if avail_resting.is_zero() {
                self.unlink_resting_slot(opp_side, best_key, head_slot, &resting, sink)
                    .map_err(InsertError::Slab)?;
                cancelled_resting.push((resting.oid, RestingCancelReason::ReduceOnly));
                continue;
            }

            let mut trade_sz = Sz(avail_resting.raw().min(remaining.raw()));

            // 3. Maker `max_trade_sz` margin clamp (`0x59120c8..0x59120e6`).
            let maker_max = risk.max_trade_sz(&resting.user, opp_side, best_px, trade_sz);
            if maker_max < trade_sz {
                cancel_resting_after = Some(RestingCancelReason::InsufficientMargin);
                trade_sz = maker_max;
                if trade_sz.is_zero() {
                    self.unlink_resting_slot(opp_side, best_key, head_slot, &resting, sink)
                        .map_err(InsertError::Slab)?;
                    cancelled_resting.push((resting.oid, RestingCancelReason::InsufficientMargin));
                    continue;
                }
            }

            // 4. Taker `max_trade_sz` margin clamp (`0x59121aa..0x59121f1`).
            let taker_max = risk.max_trade_sz(&req.user, req.side, best_px, trade_sz);
            if taker_max < trade_sz {
                trade_sz = taker_max;
                if trade_sz.is_zero() {
                    break;
                }
            }

            // Execute fill at resting order's limit price (`best_px`).
            fills.push(FillEvent {
                taker: req.user,
                maker: resting.user,
                taker_oid: req.oid,
                maker_oid: resting.oid,
                taker_side: req.side,
                px: best_px,
                sz: trade_sz,
            });
            risk.on_fill(&req.user, &resting.user, req.side, best_px, trade_sz);
            remaining = Sz(remaining.raw() - trade_sz.raw());

            if trade_sz == resting.sz || cancel_resting_after.is_some() {
                self.unlink_resting_slot(opp_side, best_key, head_slot, &resting, sink)
                    .map_err(InsertError::Slab)?;
                if let Some(reason) = cancel_resting_after {
                    cancelled_resting.push((resting.oid, reason));
                }
            } else {
                let mut total = self.total_book_sz;
                let half = match opp_side {
                    Side::Bid => &mut self.bids,
                    Side::Ask => &mut self.asks,
                };
                let lvl = half.get_mut(&best_key).expect("level exists");
                self.slab
                    .reduce_order_sz(head_slot, trade_sz, lvl, &mut total, sink);
                self.total_book_sz = total;
            }
        }

        // Rest or cancel unfilled remainder based on TIF.
        if remaining.is_zero() {
            return Ok(InsertOutcome {
                status: OrderStatus::Filled,
                fills,
                cancelled_resting,
            });
        }
        if is_ioc {
            let filled = Sz(req.sz.raw() - remaining.raw());
            return Ok(InsertOutcome {
                status: OrderStatus::IocRemainderCancelled {
                    filled,
                    cancelled: remaining,
                },
                fills,
                cancelled_resting,
            });
        }

        // Rest remaining size on own side at tail of price level (`RE-006-book-slab-link-115`).
        let key = req.side.signed_price_key(req.limit_px.raw());
        let record = OrderRecord {
            oid: req.oid,
            user: req.user,
            side: req.side,
            limit_px: req.limit_px,
            sz: remaining,
            orig_sz: req.sz,
            reduce_only: req.reduce_only,
            timestamp: req.timestamp,
            cloid: req.cloid,
            prev: None,
            next: None,
            peer_oid: None,
            parent_oid: None,
            child_oids: Vec::new(),
        };
        let mut total = self.total_book_sz;
        let slot = {
            let half = match req.side {
                Side::Bid => &mut self.bids,
                Side::Ask => &mut self.asks,
            };
            let level = half.entry(key).or_default();
            self.slab
                .insert_and_link(record, level, None, &mut total, sink)
                .map_err(InsertError::Slab)?
        };
        self.total_book_sz = total;
        self.oid_to_slot.insert(req.oid, slot);
        *self.user_open_counts.entry(req.user).or_insert(0) += 1;

        Ok(InsertOutcome {
            status: OrderStatus::Resting {
                oid: req.oid,
                remaining,
            },
            fills,
            cancelled_resting,
        })
    }

    fn unlink_resting_slot(
        &mut self,
        side: Side,
        key: i64,
        slot: SlabIndex,
        resting: &OrderRecord,
        sink: &mut impl OverflowSink,
    ) -> Result<(), SlabError> {
        let mut total = self.total_book_sz;
        let emptied = {
            let half = match side {
                Side::Bid => &mut self.bids,
                Side::Ask => &mut self.asks,
            };
            let lvl = half.get_mut(&key);
            self.slab
                .unlink(slot, lvl, &mut total, sink)?
                .map(|r| r.level_emptied)
                .unwrap_or(false)
        };
        self.total_book_sz = total;
        if emptied {
            self.half_mut(side).remove(&key);
        }
        self.oid_to_slot.remove(&resting.oid);
        if let Some(cnt) = self.user_open_counts.get_mut(&resting.user) {
            *cnt = cnt.saturating_sub(1);
            if *cnt == 0 {
                self.user_open_counts.remove(&resting.user);
            }
        }
        Ok(())
    }

    /// Cancel an order by `(user, oid)` with `#115` `0x23ce3e0` owner check and slab/level unlink.
    pub fn cancel_order(
        &mut self,
        user: &UserAddress,
        oid: u64,
        sink: &mut impl OverflowSink,
    ) -> Result<OrderRecord, CancelError> {
        let &slot = self.oid_to_slot.get(&oid).ok_or(CancelError::NotFound)?;
        let resting = self.slab.get(slot).ok_or(CancelError::NotFound)?.clone();
        if &resting.user != user {
            return Err(CancelError::WrongOwner);
        }
        let key = resting.side.signed_price_key(resting.limit_px.raw());
        self.unlink_resting_slot(resting.side, key, slot, &resting, sink)
            .map_err(CancelError::Slab)?;
        Ok(resting)
    }

    /// Modify an existing resting order (cancels `old_oid` after owner check, then inserts `new_oid`).
    pub fn modify_order(
        &mut self,
        req: ModifyOrderRequest,
        risk: &mut impl BookRiskOracle,
        sink: &mut impl OverflowSink,
    ) -> Result<(OrderRecord, InsertOutcome), ModifyError> {
        let cancelled = self
            .cancel_order(&req.user, req.old_oid, sink)
            .map_err(ModifyError::Cancel)?;
        let outcome = self
            .insert_order(
                InsertOrderRequest {
                    oid: req.new_oid,
                    user: req.user,
                    side: req.new_side,
                    limit_px: req.new_limit_px,
                    sz: req.new_sz,
                    tif: req.new_tif,
                    reduce_only: req.new_reduce_only,
                    timestamp: req.timestamp,
                    cloid: req.new_cloid,
                },
                risk,
                sink,
            )
            .map_err(ModifyError::Insert)?;
        Ok((cancelled, outcome))
    }
}

impl OrderRelations for Book {
    fn find_order_mut(&mut self, user: &UserAddress, oid: u64) -> Option<&mut OrderRecord> {
        let &slot = self.oid_to_slot.get(&oid)?;
        crate::relations::find_owned_slot_mut(&mut self.slab, slot, user)
    }
}
