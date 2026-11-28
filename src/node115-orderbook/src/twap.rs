//! TWAP execution engine joining `node115-twap-advance`, `node115-twap-quantity`,
//! `node115-twap-limit-price`, and `Book::insert_order` grounded in node #115
//! (`struct TwapState` `0x458360`, `struct TwapHeapKey` `0x5c9d18`).

use std::collections::BTreeMap;
use std::num::NonZeroU64;

use node115_assets::pdi::Side;
use node115_assets::qtys::{OverflowSink, Px, Sz};
use node115_fees::UserAddress;
use node115_tif_name_codec::Tif;
use node115_twap_advance as twap_adv;
use node115_twap_limit_price::{MarketFamily, PriceInputs, limit_price};
use node115_twap_quantity::{State as TwapQtyState, TimestampMs, plan as plan_slice};

use crate::matching::{
    Book, BookKind, BookRiskOracle, InsertError, InsertOrderRequest, InsertOutcome,
};

/// Live TWAP order metadata tracked alongside `node115_twap_advance::Tracker`.
#[derive(Clone, Debug, PartialEq)]
pub struct ActiveTwap {
    pub twap_id: u64,
    pub user: UserAddress,
    pub side: Side,
    pub reduce_only: bool,
    pub randomize: bool,
    pub tick: u64,
}

/// Result of executing one due TWAP slice against `Book`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TwapSliceExecution {
    pub twap_id: u64,
    pub user: UserAddress,
    pub slice_oid: u64,
    pub slice_limit_px: Px,
    pub slice_sz: Sz,
    pub filled_sz: Sz,
    pub finished: bool,
    pub outcome: Result<InsertOutcome, InsertError>,
}

/// Cohesive TWAP scheduling & execution engine backed by `node115-twap-advance`,
/// `node115-twap-quantity`, and `node115-twap-limit-price`.
#[derive(Default)]
pub struct TwapEngine {
    pub tracker: twap_adv::Tracker,
    pub meta: BTreeMap<(UserAddress, u64), ActiveTwap>,
}

impl TwapEngine {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new TWAP order into the min-heap scheduler (`TwapHeapKey`: `due`, `user`, `twap_id`).
    pub fn add_twap(
        &mut self,
        active: ActiveTwap,
        total_sz: Sz,
        duration_secs: f64,
        first_due: twap_adv::Moment,
    ) {
        let (days, seconds, nanos) = first_due.fields();
        let order = twap_adv::Order {
            total: total_sz.raw(),
            filled: 0,
            duration: duration_secs,
            counter: 0,
            due: first_due,
        };
        self.tracker
            .users
            .entry(active.user)
            .or_default()
            .insert(active.twap_id, order);
        self.tracker.queue.push(std::cmp::Reverse(twap_adv::QueueEntry {
            days,
            seconds,
            nanos,
            user: active.user,
            order_id: active.twap_id,
        }));
        self.meta.insert((active.user, active.twap_id), active);
    }

    /// Cancel an active TWAP order for `(user, twap_id)`.
    pub fn cancel_twap(&mut self, user: UserAddress, twap_id: u64) -> Option<ActiveTwap> {
        if let Some(user_orders) = self.tracker.users.get_mut(&user) {
            user_orders.remove(&twap_id);
            if user_orders.is_empty() {
                self.tracker.users.remove(&user);
            }
        }
        self.meta.remove(&(user, twap_id))
    }

    /// Select this pass's due keys before executing any returned slice.
    pub fn take_due(&mut self, now: twap_adv::Moment) -> Vec<(UserAddress, u64)> {
        self.tracker.take_due(now)
    }

    /// Execute one due TWAP slice at `(now, now_ms)` against `book`, using `#115`
    /// `node115-twap-limit-price`, `node115-twap-quantity`, and `node115-twap-advance`.
    #[allow(clippy::too_many_arguments)]
    pub fn execute_slice(
        &mut self,
        user: UserAddress,
        twap_id: u64,
        slice_oid: u64,
        now: twap_adv::Moment,
        now_ms: u64,
        spot_mid_override: Option<Px>,
        book: &mut Book,
        risk: &mut impl BookRiskOracle,
        sink: &mut impl OverflowSink,
    ) -> Option<TwapSliceExecution> {
        let active = self.meta.get(&(user, twap_id))?.clone();
        let current = *self.tracker.users.get(&user)?.get(&twap_id)?;

        let (top_bid, top_ask) = book.bbo();
        let family = match book.kind() {
            BookKind::Perp => MarketFamily::Perp,
            BookKind::Spot => MarketFamily::Spot,
        };
        let spot_mid = spot_mid_override
            .or_else(|| book.mid_px())
            .map(Px::raw)
            .unwrap_or(0);
        let px_raw = limit_price(PriceInputs {
            family,
            side: active.side.as_u8(),
            top_bid: top_bid.map(Px::raw).unwrap_or(0),
            top_ask: top_ask.map(Px::raw).unwrap_or(0),
            spot_mid,
            tick: active.tick,
        })?;
        let nz_px = NonZeroU64::new(px_raw)?;
        let ts = TimestampMs::new(now_ms)?;

        let planned = plan_slice(
            TwapQtyState {
                total: current.total,
                filled: current.filled,
                slice_index: current.counter,
                duration: current.duration,
                jitter: active.randomize,
            },
            nz_px,
            ts,
        )?;

        let slice_sz = Sz(planned.quantity);
        let slice_px = Px(px_raw);
        let outcome = if slice_sz.is_zero() {
            Err(InsertError::ZeroSize)
        } else {
            book.insert_order(
                InsertOrderRequest {
                    oid: slice_oid,
                    user,
                    side: active.side,
                    limit_px: slice_px,
                    sz: slice_sz,
                    tif: Tif::Ioc,
                    reduce_only: active.reduce_only,
                    timestamp: now_ms,
                    cloid: None,
                },
                risk,
                sink,
            )
        };

        let filled_raw: u64 = match &outcome {
            Ok(res) => res.fills.iter().map(|f| f.sz.raw()).sum(),
            Err(_) => 0,
        };
        if let Some(ord) = self.tracker.users.get_mut(&user).and_then(|m| m.get_mut(&twap_id)) {
            ord.filled = ord.filled.saturating_add(filled_raw);
        }

        let adv = twap_adv::advance(&mut self.tracker, user, twap_id, now);
        let finished = matches!(adv, twap_adv::Outcome::Finish);
        if finished {
            self.cancel_twap(user, twap_id);
        }

        Some(TwapSliceExecution {
            twap_id,
            user,
            slice_oid,
            slice_limit_px: slice_px,
            slice_sz,
            filled_sz: Sz(filled_raw),
            finished,
            outcome,
        })
    }
}
