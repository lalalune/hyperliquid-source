//! Trigger and TP/SL orders grounded in node #115 `.rodata` schemas:
//! - `struct Trigger` (3 elements, `0x5ca088`)
//! - `struct TriggerOrder` (2 elements, `0x5ca3a8`)
//! - `tpsl` enum (`0x5ed239`, 2 variants: `Tp`/`Sl`, `is_position_tpsl` `0x453b8c`)
//! - `OrderDescription` (`0x5eaf9d`: `Limit`, `Market`, `TakeProfitLimit`, `TakeProfitMarket`,
//!   `StopLimit`, `StopMarket`).

use std::collections::BTreeMap;

use node115_assets::pdi::Side;
use node115_assets::qtys::{OverflowSink, Px, Sz};
use node115_fees::UserAddress;
use node115_tif_name_codec::Tif;

use crate::matching::{Book, BookRiskOracle, InsertError, InsertOrderRequest, InsertOutcome};

/// Take-profit vs stop-loss classification (`tpsl` `0 <= i < 2` at `#115` `0x5ed239`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Tpsl {
    Tp = 0,
    Sl = 1,
}

/// Order description variants observed verbatim at `#115` `.rodata` `0x5eaf9d`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OrderDescription {
    Limit,
    Market,
    TakeProfitLimit,
    TakeProfitMarket,
    StopLimit,
    StopMarket,
}

/// Trigger condition matching `#115` `struct Trigger` (3 elements: `is_market`, `trigger_px`, `tpsl`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TriggerCondition {
    pub is_market: bool,
    pub trigger_px: Px,
    pub tpsl: Tpsl,
}

impl TriggerCondition {
    /// Returns true when `mark_px` activates this trigger for an order on `side`:
    /// - `Ask` (selling): `Tp` fires when `mark_px >= trigger_px`; `Sl` fires when `mark_px <= trigger_px`.
    /// - `Bid` (buying): `Tp` fires when `mark_px <= trigger_px`; `Sl` fires when `mark_px >= trigger_px`.
    #[inline]
    pub const fn should_trigger(self, side: Side, mark_px: Px) -> bool {
        match (side, self.tpsl) {
            (Side::Ask, Tpsl::Tp) | (Side::Bid, Tpsl::Sl) => mark_px.raw() >= self.trigger_px.raw(),
            (Side::Bid, Tpsl::Tp) | (Side::Ask, Tpsl::Sl) => mark_px.raw() <= self.trigger_px.raw(),
        }
    }

    #[inline]
    pub const fn description(self) -> OrderDescription {
        match (self.tpsl, self.is_market) {
            (Tpsl::Tp, false) => OrderDescription::TakeProfitLimit,
            (Tpsl::Tp, true) => OrderDescription::TakeProfitMarket,
            (Tpsl::Sl, false) => OrderDescription::StopLimit,
            (Tpsl::Sl, true) => OrderDescription::StopMarket,
        }
    }
}

/// Resting trigger order waiting for mark/oracle price activation (`struct TriggerOrder`, `0x5ca3a8`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TriggerOrder {
    pub oid: u64,
    pub user: UserAddress,
    pub side: Side,
    pub limit_px: Px,
    pub sz: Sz,
    pub reduce_only: bool,
    pub is_position_tpsl: bool,
    pub trigger: TriggerCondition,
    pub timestamp: u64,
    pub cloid: Option<[u8; 16]>,
    /// Optional OCO peer trigger OID cancelled automatically when this order triggers.
    pub peer_oid: Option<u64>,
}

/// Result of evaluating resting trigger orders against a new mark price.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TriggerFireResult {
    pub oid: u64,
    pub cancelled_peer_oid: Option<u64>,
    pub outcome: Result<InsertOutcome, InsertError>,
}

/// Per-asset trigger / TP-SL order store (`TriggerBook`).
#[derive(Clone, Debug, Default)]
pub struct TriggerBook {
    orders: BTreeMap<u64, TriggerOrder>,
}

impl TriggerBook {
    pub fn new() -> Self {
        Self::default()
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.orders.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.orders.is_empty()
    }

    pub fn insert(&mut self, order: TriggerOrder) -> Option<TriggerOrder> {
        self.orders.insert(order.oid, order)
    }

    pub fn get(&self, oid: u64) -> Option<&TriggerOrder> {
        self.orders.get(&oid)
    }

    /// Link two resting trigger orders as mutual OCO peers (matching `relations::link_peers`).
    pub fn link_oco_peers(&mut self, user: &UserAddress, first_oid: u64, second_oid: u64) {
        if let Some(a) = self.orders.get_mut(&first_oid)
            && &a.user == user
        {
            a.peer_oid = Some(second_oid);
        }
        if let Some(b) = self.orders.get_mut(&second_oid)
            && &b.user == user
        {
            b.peer_oid = Some(first_oid);
        }
    }

    /// Cancel a resting trigger order after verifying the 20-byte owner.
    pub fn cancel(&mut self, user: &UserAddress, oid: u64) -> Option<TriggerOrder> {
        let owned = self.orders.get(&oid).is_some_and(|o| &o.user == user);
        if !owned {
            return None;
        }
        self.orders.remove(&oid)
    }

    /// Cancel all resting trigger orders for `user`.
    pub fn cancel_all_for_user(&mut self, user: &UserAddress) -> Vec<TriggerOrder> {
        let oids: Vec<u64> = self
            .orders
            .iter()
            .filter_map(|(&oid, o)| (&o.user == user).then_some(oid))
            .collect();
        oids.into_iter()
            .filter_map(|oid| self.orders.remove(&oid))
            .collect()
    }

    /// Evaluate all resting triggers against `mark_px` in deterministic OID order,
    /// firing activated orders into `book` (cancelling any OCO peer first).
    pub fn trigger_on_mark(
        &mut self,
        mark_px: Px,
        now: u64,
        book: &mut Book,
        risk: &mut impl BookRiskOracle,
        sink: &mut impl OverflowSink,
    ) -> Vec<TriggerFireResult> {
        let candidates: Vec<u64> = self
            .orders
            .iter()
            .filter_map(|(&oid, o)| o.trigger.should_trigger(o.side, mark_px).then_some(oid))
            .collect();

        let mut results = Vec::new();
        for oid in candidates {
            // May have already been cancelled as an OCO peer of an earlier triggered order.
            let Some(order) = self.orders.remove(&oid) else {
                continue;
            };
            let mut cancelled_peer_oid = None;
            if let Some(peer) = order.peer_oid
                && self.orders.get(&peer).is_some_and(|p| p.user == order.user)
            {
                self.orders.remove(&peer);
                cancelled_peer_oid = Some(peer);
            }
            let tif = if order.trigger.is_market {
                Tif::FrontendMarket
            } else {
                Tif::Gtc
            };
            let outcome = book.insert_order(
                InsertOrderRequest {
                    oid: order.oid,
                    user: order.user,
                    side: order.side,
                    limit_px: order.limit_px,
                    sz: order.sz,
                    tif,
                    reduce_only: order.reduce_only,
                    timestamp: now,
                    cloid: order.cloid,
                },
                risk,
                sink,
            );
            results.push(TriggerFireResult {
                oid: order.oid,
                cancelled_peer_oid,
                outcome,
            });
        }
        results
    }
}
