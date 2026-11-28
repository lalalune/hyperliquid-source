use node115_assets::pdi::{PerpAsset, Side};
use node115_assets::qtys::{NoopOverflowSink, Px, RecordingOverflowSink, Sz, Szi};
use node115_fees::vlm::{
    OpenOrderDecision, OpenOrderDescriptor, PRIVILEGED_OPEN_ORDER_ADDRESSES, UserVolumeTotals,
};
use node115_orderbook::books::Books;
use node115_orderbook::matching::{
    Book, BookRiskOracle, CancelError, InsertError, InsertOrderRequest, ModifyOrderRequest,
    OrderStatus, RestingCancelReason, UnboundedRiskOracle, cancel_oid_hash, would_cross,
};
use node115_orderbook::relations::{detach_from_parent, link_peers};
use node115_orderbook::slab::{Level, OrderRecord, OrderSlab};
use node115_orderbook::tif_name_codec::Tif;
use node115_orderbook::{open_interest_cap, twap_limit_price};

fn user(tag: u8) -> [u8; 20] {
    [tag; 20]
}

fn order_req(
    oid: u64,
    u: [u8; 20],
    side: Side,
    px: u64,
    sz: u64,
    tif: Tif,
    reduce_only: bool,
) -> InsertOrderRequest {
    InsertOrderRequest {
        oid,
        user: u,
        side,
        limit_px: Px(px),
        sz: Sz(sz),
        tif,
        reduce_only,
        timestamp: oid * 10,
        cloid: None,
    }
}

#[test]
fn tif_alo_ioc_gtc_and_fifo_matching() {
    let mut book = Book::new();
    let mut risk = UnboundedRiskOracle::default();
    let mut sink = NoopOverflowSink;

    // Rest two asks at 100 (FIFO: oid 1 then oid 2) and one ask at 105 (oid 3).
    let r1 = book
        .insert_order(order_req(1, user(1), Side::Ask, 100, 10, Tif::Gtc, false), &mut risk, &mut sink)
        .unwrap();
    assert_eq!(r1.status, OrderStatus::Resting { oid: 1, remaining: Sz(10) });

    book.insert_order(order_req(2, user(2), Side::Ask, 100, 15, Tif::Gtc, false), &mut risk, &mut sink)
        .unwrap();
    book.insert_order(order_req(3, user(3), Side::Ask, 105, 20, Tif::Gtc, false), &mut risk, &mut sink)
        .unwrap();
    assert_eq!(book.bbo(), (None, Some(Px(100))));

    // ALO bid at 100 crosses best ask -> BadAloPx with current BBO (`0x59025c6`).
    assert_eq!(
        book.insert_order(order_req(4, user(4), Side::Bid, 100, 5, Tif::Alo, false), &mut risk, &mut sink),
        Err(InsertError::BadAloPx {
            bbo: (None, Some(Px(100))),
        })
    );

    // ALO bid at 99 does NOT cross -> rests cleanly.
    book.insert_order(order_req(5, user(4), Side::Bid, 99, 8, Tif::Alo, false), &mut risk, &mut sink)
        .unwrap();
    assert_eq!(book.bbo(), (Some(Px(99)), Some(Px(100))));
    assert_eq!(book.mid_px(), Some(Px(99)));

    // IOC bid at 99 does NOT cross -> immediate IocCancel (`0x59025b0`).
    assert_eq!(
        book.insert_order(order_req(6, user(5), Side::Bid, 99, 5, Tif::Ioc, false), &mut risk, &mut sink),
        Err(InsertError::IocCancel)
    );

    // GTC bid at 102 for size 18 sweeps oid 1 (10) then partial oid 2 (8), leaving 7 on oid 2.
    let sweep = book
        .insert_order(order_req(7, user(5), Side::Bid, 102, 18, Tif::Gtc, false), &mut risk, &mut sink)
        .unwrap();
    assert_eq!(sweep.status, OrderStatus::Filled);
    assert_eq!(sweep.fills.len(), 2);
    assert_eq!((sweep.fills[0].maker_oid, sweep.fills[0].px, sweep.fills[0].sz), (1, Px(100), Sz(10)));
    assert_eq!((sweep.fills[1].maker_oid, sweep.fills[1].px, sweep.fills[1].sz), (2, Px(100), Sz(8)));
    assert_eq!(book.get_order(1), None);
    assert_eq!(book.get_order(2).unwrap().sz, Sz(7));

    // IOC bid at 100 for size 12 fills remaining 7 of oid 2 and cancels 5.
    let ioc = book
        .insert_order(order_req(8, user(6), Side::Bid, 100, 12, Tif::Ioc, false), &mut risk, &mut sink)
        .unwrap();
    assert_eq!(
        ioc.status,
        OrderStatus::IocRemainderCancelled {
            filled: Sz(7),
            cancelled: Sz(5),
        }
    );
    assert_eq!(book.bbo(), (Some(Px(99)), Some(Px(105))));
}

#[test]
fn self_trade_prevention_identical_user_and_hlp_vaults() {
    let mut book = Book::new();
    let mut risk = UnboundedRiskOracle::default();
    let mut sink = NoopOverflowSink;

    // 1. Same user self-trade cancels resting order (`0x5911e73`).
    book.insert_order(order_req(10, user(1), Side::Ask, 100, 5, Tif::Gtc, false), &mut risk, &mut sink)
        .unwrap();
    let out = book
        .insert_order(order_req(11, user(1), Side::Bid, 100, 5, Tif::Gtc, false), &mut risk, &mut sink)
        .unwrap();
    assert!(out.fills.is_empty());
    assert_eq!(out.cancelled_resting, vec![(10, RestingCancelReason::SelfTrade)]);
    assert_eq!(out.status, OrderStatus::Resting { oid: 11, remaining: Sz(5) });

    // 2. Mutual 8-address HLP vault self-trade guard (`0x5911eb8`, `0x421a520`).
    let vault_a = PRIVILEGED_OPEN_ORDER_ADDRESSES[0];
    let vault_b = PRIVILEGED_OPEN_ORDER_ADDRESSES[1];
    book.insert_order(order_req(20, vault_a, Side::Ask, 200, 10, Tif::Gtc, false), &mut risk, &mut sink)
        .unwrap();
    let out2 = book
        .insert_order(order_req(21, vault_b, Side::Bid, 200, 10, Tif::Gtc, false), &mut risk, &mut sink)
        .unwrap();
    assert!(out2.fills.is_empty());
    assert_eq!(out2.cancelled_resting, vec![(20, RestingCancelReason::SelfTrade)]);
}

#[test]
fn resting_reduce_only_and_margin_clamping() {
    struct CappedRisk {
        inner: UnboundedRiskOracle,
        maker_cap: Sz,
    }
    impl BookRiskOracle for CappedRisk {
        fn signed_position(&self, user: &node115_fees::UserAddress) -> Szi {
            self.inner.signed_position(user)
        }
        fn max_trade_sz(&self, user: &node115_fees::UserAddress, side: Side, px: Px, requested: Sz) -> Sz {
            if *user == [9; 20] {
                Sz(requested.raw().min(self.maker_cap.raw()))
            } else {
                self.inner.max_trade_sz(user, side, px, requested)
            }
        }
        fn on_fill(&mut self, t: &node115_fees::UserAddress, m: &node115_fees::UserAddress, s: Side, px: Px, sz: Sz) {
            self.inner.on_fill(t, m, s, px, sz);
        }
    }

    let mut book = Book::new();
    let mut risk = CappedRisk {
        inner: UnboundedRiskOracle::default(),
        maker_cap: Sz(3),
    };
    let mut sink = NoopOverflowSink;

    // Resting reduce-only Ask with 0 position -> cancelled with ReduceOnly (`0x5911f83`).
    book.insert_order(order_req(30, user(2), Side::Ask, 100, 10, Tif::Gtc, true), &mut risk, &mut sink)
        .unwrap();
    // Resting reduce-only Ask with +4 long position (order is 10) -> fills 4 then cancels remainder (`0x5911fe2`).
    risk.inner.positions.insert(user(3), Szi(4));
    book.insert_order(order_req(31, user(3), Side::Ask, 100, 10, Tif::Gtc, true), &mut risk, &mut sink)
        .unwrap();
    // Resting Ask from maker [9;20] capped to 3 by margin -> fills 3 then cancels (`0x59120d8`).
    book.insert_order(order_req(32, user(9), Side::Ask, 100, 10, Tif::Gtc, false), &mut risk, &mut sink)
        .unwrap();

    let out = book
        .insert_order(order_req(33, user(1), Side::Bid, 100, 20, Tif::Gtc, false), &mut risk, &mut sink)
        .unwrap();
    assert_eq!(out.fills.len(), 2);
    assert_eq!((out.fills[0].maker_oid, out.fills[0].sz), (31, Sz(4)));
    assert_eq!((out.fills[1].maker_oid, out.fills[1].sz), (32, Sz(3)));
    assert_eq!(
        out.cancelled_resting,
        vec![
            (30, RestingCancelReason::ReduceOnly),
            (31, RestingCancelReason::ReduceOnly),
            (32, RestingCancelReason::InsufficientMargin),
        ]
    );
    assert_eq!(out.status, OrderStatus::Resting { oid: 33, remaining: Sz(13) });
}

#[test]
fn slab_recycling_peer_links_cancel_modify_and_books() {
    let mut sink = RecordingOverflowSink::default();

    // Direct slab insert-before + unlink cursor advance (`RE-006-book-slab-link-115`).
    let mut slab = OrderSlab::new();
    let mut lvl = Level::default();
    let mut total = Sz::ZERO;
    let mk = |oid: u64, sz: u64| OrderRecord {
        oid,
        user: user(1),
        side: Side::Bid,
        limit_px: Px(50),
        sz: Sz(sz),
        orig_sz: Sz(sz),
        reduce_only: false,
        timestamp: 0,
        cloid: None,
        prev: None,
        next: None,
        peer_oid: None,
        parent_oid: None,
        child_oids: Vec::new(),
    };
    let s0 = slab.insert_and_link(mk(1, 10), &mut lvl, None, &mut total, &mut sink).unwrap();
    let s1 = slab.insert_and_link(mk(2, 20), &mut lvl, Some(s0), &mut total, &mut sink).unwrap();
    assert_eq!(slab.level_slots(&lvl), vec![s1, s0]);
    lvl.cursor = Some(s1);
    let u = slab.unlink(s1, Some(&mut lvl), &mut total, &mut sink).unwrap().unwrap();
    assert!(!u.level_emptied);
    assert_eq!(lvl.cursor, Some(s0));
    // Recycling reuses slot `s1`.
    let s2 = slab.insert_and_link(mk(3, 5), &mut lvl, None, &mut total, &mut sink).unwrap();
    assert_eq!(s2, s1);

    // Multi-asset Books + peer link + parent detach + cancel owner guard + modify.
    let mut books = Books::<PerpAsset>::new();
    let mut risk = UnboundedRiskOracle::default();
    let btc = PerpAsset(0);

    books
        .insert_order(btc, order_req(100, user(1), Side::Bid, 500, 10, Tif::Gtc, false), &mut risk, &mut sink)
        .unwrap();
    books
        .insert_order(btc, order_req(101, user(1), Side::Bid, 499, 10, Tif::Gtc, false), &mut risk, &mut sink)
        .unwrap();
    {
        let b = books.get_mut(&btc).unwrap();
        link_peers(b, &user(1), 100, 101);
        assert_eq!(b.get_order(100).unwrap().peer_oid, Some(101));
        assert_eq!(b.get_order(101).unwrap().peer_oid, Some(100));

        // Parent detach removes all duplicate child occurrences (`RE-006-book-peer-links-115`).
        use node115_orderbook::relations::OrderRelations;
        b.find_order_mut(&user(1), 100).unwrap().child_oids = vec![101, 999, 101];
        b.find_order_mut(&user(1), 101).unwrap().parent_oid = Some(100);
        detach_from_parent(b, &user(1), 101);
        assert_eq!(b.get_order(101).unwrap().parent_oid, None);
        assert_eq!(b.get_order(100).unwrap().child_oids, vec![999]);
    }

    // Wrong owner cannot cancel (`0x23ce4ea`).
    assert_eq!(
        books.cancel_order(&btc, &user(2), 100, &mut sink),
        Err(CancelError::WrongOwner)
    );
    // Modify replaces oid 100 with oid 102.
    let (old, outcome) = books
        .modify_order(
            &btc,
            ModifyOrderRequest {
                old_oid: 100,
                new_oid: 102,
                user: user(1),
                new_side: Side::Bid,
                new_limit_px: Px(505),
                new_sz: Sz(12),
                new_tif: Tif::Gtc,
                new_reduce_only: false,
                timestamp: 200,
                new_cloid: None,
            },
            &mut risk,
            &mut sink,
        )
        .unwrap();
    assert_eq!(old.oid, 100);
    assert_eq!(outcome.status, OrderStatus::Resting { oid: 102, remaining: Sz(12) });
    assert_eq!(books.bbo(&btc), (Some(Px(505)), None));

    // Verify helper cross-checks and micro-crate interop.
    assert!(would_cross(Side::Bid, Px(100), Some(Px(100))));
    assert!(!would_cross(Side::Bid, Px(99), Some(Px(100))));
    assert!(would_cross(Side::Ask, Px(100), Some(Px(100))));
    assert_eq!(cancel_oid_hash(0), 0);
    assert_eq!(
        books.get(&btc).unwrap().check_user_open_order_cap(
            &user(1),
            OpenOrderDescriptor::Other { flag_31: false, tag_19: 2 },
            &[],
            UserVolumeTotals::default(),
            &mut sink,
        ),
        OpenOrderDecision::Pass
    );
    let _ = open_interest_cap::project(open_interest_cap::Input {
        sum_left: 100,
        sum_right: 50,
        multiplier: 1,
        key: 0,
        selector: 0,
        observed_cap_word: 1_000,
    });
    assert_eq!(
        twap_limit_price::limit_price(twap_limit_price::PriceInputs {
            family: twap_limit_price::MarketFamily::Perp,
            side: 0,
            top_bid: 99_000,
            top_ask: 101_000,
            spot_mid: 0,
            tick: 10,
        }),
        Some(103_000)
    );
}

#[test]
fn cloid_spot_oi_cap_trigger_oco_twap_and_schedule_cancel() {
    use node115_orderbook::{
        ActiveTwap, BookKind, OrderDescription, ScheduleCancelEngine, Tpsl, TriggerBook,
        TriggerCondition, TriggerOrder, TwapEngine, schedule_cancel, twap_advance,
    };

    let mut sink = NoopOverflowSink;
    let mut risk = UnboundedRiskOracle::default();

    // 1. Perp OI cap + CLOID cancel + last_trade_px
    let mut perp = Book::new_with_kind(BookKind::Perp);
    perp.set_open_interest_cap(Some(Sz(1_000)), Sz(1_000));
    let cloid_a = [0xAB; 16];
    // Non-reduce-only blocked at OI cap
    assert_eq!(
        perp.insert_order(
            InsertOrderRequest {
                cloid: Some(cloid_a),
                ..order_req(200, user(1), Side::Bid, 100, 10, Tif::Gtc, false)
            },
            &mut risk,
            &mut sink,
        ),
        Err(InsertError::OpenInterestCapExceeded)
    );
    // Reduce-only is STILL allowed at OI cap
    perp.insert_order(
        InsertOrderRequest {
            cloid: Some(cloid_a),
            ..order_req(201, user(1), Side::Bid, 100, 10, Tif::Gtc, true)
        },
        &mut risk,
        &mut sink,
    )
    .unwrap();
    assert_eq!(perp.get_order_by_cloid(&user(1), cloid_a).unwrap().oid, 201);
    // Duplicate CLOID for same user rejected
    assert_eq!(
        perp.insert_order(
            InsertOrderRequest {
                cloid: Some(cloid_a),
                ..order_req(202, user(1), Side::Bid, 101, 5, Tif::Gtc, true)
            },
            &mut risk,
            &mut sink,
        ),
        Err(InsertError::DuplicateCloid(cloid_a))
    );
    // Cancel by CLOID clears cloid_tracker
    assert_eq!(perp.cancel_by_cloid(&user(1), cloid_a, &mut sink).unwrap().oid, 201);
    assert!(perp.get_order_by_cloid(&user(1), cloid_a).is_none());

    // 2. Spot book ignores Perp OI cap and tracks last_trade_px
    let mut spot = Book::new_with_kind(BookKind::Spot);
    spot.set_open_interest_cap(Some(Sz(0)), Sz(0));
    spot.insert_order(order_req(300, user(2), Side::Ask, 10_000, 50, Tif::Gtc, false), &mut risk, &mut sink)
        .unwrap();
    spot.insert_order(order_req(301, user(1), Side::Bid, 9_800, 50, Tif::Gtc, false), &mut risk, &mut sink)
        .unwrap();
    assert_eq!(spot.last_trade_px(), None);

    // 3. Trigger / TP-SL with OCO peer cancel
    let mut triggers = TriggerBook::new();
    let tp_cond = TriggerCondition {
        is_market: true,
        trigger_px: Px(10_500),
        tpsl: Tpsl::Tp,
    };
    let sl_cond = TriggerCondition {
        is_market: false,
        trigger_px: Px(9_500),
        tpsl: Tpsl::Sl,
    };
    assert_eq!(tp_cond.description(), OrderDescription::TakeProfitMarket);
    assert_eq!(sl_cond.description(), OrderDescription::StopLimit);
    triggers.insert(TriggerOrder {
        oid: 400,
        user: user(3),
        side: Side::Ask,
        limit_px: Px(9_000),
        sz: Sz(10),
        reduce_only: false,
        is_position_tpsl: true,
        trigger: tp_cond,
        timestamp: 1,
        cloid: None,
        peer_oid: None,
    });
    triggers.insert(TriggerOrder {
        oid: 401,
        user: user(3),
        side: Side::Ask,
        limit_px: Px(9_400),
        sz: Sz(10),
        reduce_only: false,
        is_position_tpsl: true,
        trigger: sl_cond,
        timestamp: 1,
        cloid: None,
        peer_oid: None,
    });
    triggers.link_oco_peers(&user(3), 400, 401);
    // Mark 10_000 triggers neither
    assert!(triggers.trigger_on_mark(Px(10_000), 2, &mut spot, &mut risk, &mut sink).is_empty());
    // Mark 10_500 triggers TP (400), cancels OCO peer SL (401), and fills against resting bid 301 at 9_800!
    let fired = triggers.trigger_on_mark(Px(10_500), 3, &mut spot, &mut risk, &mut sink);
    assert_eq!(fired.len(), 1);
    assert_eq!(fired[0].oid, 400);
    assert_eq!(fired[0].cancelled_peer_oid, Some(401));
    assert!(triggers.is_empty());
    assert_eq!(spot.last_trade_px(), Some(Px(9_800)));

    // 4. Live TwapEngine executing a slice against the book
    let mut twap = TwapEngine::new();
    let now = twap_advance::Moment::new(739_000, 100, 0).unwrap();
    twap.add_twap(
        ActiveTwap {
            twap_id: 500,
            user: user(4),
            side: Side::Bid,
            reduce_only: false,
            randomize: false,
            tick: 10,
        },
        Sz(20),
        60.0,
        now,
    );
    let exec = twap
        .execute_slice(user(4), 500, 501, now, 1_700_000_000_000, Some(Px(9_900)), &mut spot, &mut risk, &mut sink)
        .unwrap();
    assert!(exec.slice_sz.raw() > 0);
    assert!(exec.filled_sz.raw() > 0);
    assert_eq!(spot.last_trade_px(), Some(Px(10_000)));

    // 5. ScheduleCancelEngine dead-man's-switch cancels all resting orders for user(1)
    let mut sc_engine = ScheduleCancelEngine::new();
    let sc_now = schedule_cancel::Moment::from_unix_millis(1_700_000_000_000).unwrap();
    let mut vols = schedule_cancel::Volumes::default();
    vols.spot.insert(
        user(1),
        schedule_cancel::Volume {
            scaled: 2_000_000_000_000,
            raw: 2_000_000_000_000,
        },
    );
    let _ = sc_engine.request(user(1), sc_now, Some(1_700_000_010_000), &vols);
    let sc_later = schedule_cancel::Moment::from_unix_millis(1_700_000_020_000).unwrap();
    let swept = sc_engine.fire_due(sc_later, &mut [&mut spot], &mut sink);
    assert_eq!(swept.len(), 1);
    assert_eq!(swept[0].0, user(1));
    assert_eq!(spot.open_order_count(&user(1)), 0);
}

#[test]
fn priority_level_queue_splicing_modify_sz_diff_and_layout_match_node115() {
    use node115_orderbook::{
        BOOK_STRUCT_STRIDE_BYTES, LEVEL_INSERT_DIFF_BYTES, LEVEL_MODIFY_DIFF_BYTES,
        PERP_DEX_STRUCT_STRIDE_BYTES, PRIORITY_RING_ENTRY_BYTES, LevelDiffEvent, PriorityKey,
        PriorityLevelQueue, SLAB_ENTRY_STRIDE_BYTES,
    };

    // Exact node #115 layout constants (`0x22e7590`, `0x276e000`, `0x58df360`, `0x25da200`, `0x5911890`).
    assert_eq!(BOOK_STRUCT_STRIDE_BYTES, 288);
    assert_eq!(PERP_DEX_STRUCT_STRIDE_BYTES, 512);
    assert_eq!(SLAB_ENTRY_STRIDE_BYTES, 272);
    assert_eq!(LEVEL_INSERT_DIFF_BYTES, 696);
    assert_eq!(LEVEL_MODIFY_DIFF_BYTES, 712);
    assert_eq!(PRIORITY_RING_ENTRY_BYTES, 32);

    // Exact `#115` `0x4dce580` key ordering: priority DESC, then oid ASC.
    assert!(
        PriorityKey { oid: 10, priority: 5 } < PriorityKey { oid: 1, priority: 2 }
    );
    assert!(
        PriorityKey { oid: 1, priority: 5 } < PriorityKey { oid: 2, priority: 5 }
    );

    let mut slab = OrderSlab::new();
    let mut queue = PriorityLevelQueue::new();
    let mut book_total = Sz::ZERO;
    let mut diffs = Vec::new();
    let mut sink = RecordingOverflowSink::default();

    let mk = |oid: u64, sz: u64| OrderRecord {
        oid,
        user: user(1),
        side: Side::Bid,
        limit_px: Px(1_000),
        sz: Sz(sz),
        orig_sz: Sz(sz),
        reduce_only: false,
        timestamp: oid,
        cloid: None,
        prev: None,
        next: None,
        peer_oid: None,
        parent_oid: None,
        child_oids: Vec::new(),
    };

    // 1. Non-priority order 100 initializes `level.cursor` (first non-priority).
    let s100 = queue
        .insert_resting(&mut slab, mk(100, 10), None, 1, &mut book_total, &mut diffs, &mut sink)
        .unwrap();
    assert_eq!(queue.level.cursor, Some(s100));

    // 2. Non-priority order 101 appends after 100; cursor stays at s100.
    let s101 = queue
        .insert_resting(&mut slab, mk(101, 20), None, 2, &mut book_total, &mut diffs, &mut sink)
        .unwrap();
    assert_eq!(queue.level.cursor, Some(s100));

    // 3. Priority-2 order 102 splices before first non-priority (s100).
    let s102 = queue
        .insert_resting(&mut slab, mk(102, 5), Some(2), 3, &mut book_total, &mut diffs, &mut sink)
        .unwrap();
    // 4. Priority-5 order 103 splices before priority-2 (s102).
    let s103 = queue
        .insert_resting(&mut slab, mk(103, 7), Some(5), 4, &mut book_total, &mut diffs, &mut sink)
        .unwrap();
    // 5. Priority-5 order 104 (higher OID) splices after 103 and before priority-2 (s102).
    let s104 = queue
        .insert_resting(&mut slab, mk(104, 8), Some(5), 5, &mut book_total, &mut diffs, &mut sink)
        .unwrap();

    // Expected queue order: [103 (p=5), 104 (p=5), 102 (p=2), 100 (none), 101 (none)].
    let oids: Vec<u64> = slab
        .level_slots(&queue.level)
        .into_iter()
        .map(|s| slab.get(s).unwrap().oid)
        .collect();
    assert_eq!(oids, vec![103, 104, 102, 100, 101]);
    assert_eq!(queue.priority_ring.len(), 3);
    assert_eq!(book_total, Sz(50));
    assert_eq!(queue.level.total_sz, Sz(50));

    // 6. Modify size (`0x25da200`): no-op on identical size; updates totals & emits diff on change.
    assert!(!queue
        .modify_order_sz(&mut slab, s104, Sz(8), 6, &mut book_total, &mut diffs, &mut sink)
        .unwrap());
    assert!(queue
        .modify_order_sz(&mut slab, s104, Sz(18), 7, &mut book_total, &mut diffs, &mut sink)
        .unwrap());
    assert_eq!(book_total, Sz(60));
    assert_eq!(queue.level.total_sz, Sz(60));
    assert_eq!(
        diffs.last().copied(),
        Some(LevelDiffEvent::OrderSizeModified {
            oid: 104,
            user: user(1),
            side: Side::Bid,
            px: Px(1_000),
            old_sz: Sz(8),
            new_sz: Sz(18),
            timestamp: 7,
        })
    );

    // 7. Removing cursor (`s100`) advances `level.cursor` to `s101` (`0x58dfbc0`).
    let removed_100 = queue
        .remove_order(&mut slab, s100, None, &mut book_total, &mut diffs, &mut sink)
        .unwrap()
        .unwrap();
    assert!(!removed_100.level_emptied);
    assert_eq!(queue.level.cursor, Some(s101));

    // Removing priority order `s103` removes it from `priority_orders`.
    queue
        .remove_order(&mut slab, s103, Some(5), &mut book_total, &mut diffs, &mut sink)
        .unwrap()
        .unwrap();
    assert!(!queue.priority_orders.contains_key(&PriorityKey { oid: 103, priority: 5 }));
    assert_eq!(book_total, Sz(43));
    assert_eq!(queue.level.total_sz, Sz(43));
    assert!(sink.events.is_empty());
    let _ = (s102, s104);
}

#[test]
fn impact_walk_l2_aggregation_and_order_price_shape_match_node115() {
    use node115_assets::qtys::Ntl;
    use node115_orderbook::{
        MAX_IMPACT_NOTIONAL_PRODUCT, MAX_SHAPED_NOTIONAL_CAP, PriceMove, PriceShapeContext,
        PriceShapeError, PriceShapeRequest, SYSTEM_USER_EE, SYSTEM_USER_FF, bucket_l2_px,
        impact_walk_levels, shape_order_price,
    };

    let mut book = Book::new();
    let mut risk = UnboundedRiskOracle::default();
    let mut sink = RecordingOverflowSink::default();

    // Populate Bids (1000x50, 995x100, 990x200) and Asks (1005x40, 1010x100, 1020x200)
    book.insert_order(order_req(1, user(1), Side::Bid, 1000, 50, Tif::Gtc, false), &mut risk, &mut sink).unwrap();
    book.insert_order(order_req(2, user(1), Side::Bid, 995, 100, Tif::Gtc, false), &mut risk, &mut sink).unwrap();
    book.insert_order(order_req(3, user(1), Side::Bid, 990, 200, Tif::Gtc, false), &mut risk, &mut sink).unwrap();
    book.insert_order(order_req(4, user(2), Side::Ask, 1005, 40, Tif::Gtc, false), &mut risk, &mut sink).unwrap();
    book.insert_order(order_req(5, user(2), Side::Ask, 1010, 100, Tif::Gtc, false), &mut risk, &mut sink).unwrap();
    book.insert_order(order_req(6, user(2), Side::Ask, 1020, 200, Tif::Gtc, false), &mut risk, &mut sink).unwrap();

    // Impact walk (`0x46a6370`): target_ntl = 100_000
    // Bid side: lvl1 1000*50=50_000 (<100k); lvl2 rem=50_000 -> q=50_000/995=50, p=49_750, total=99_750, count=100 -> floor(99750/100)=997
    // Ask side: lvl1 1005*40=40_200 (<100k); lvl2 rem=59_800 -> q=59_800/1010=59, p=59_590, total=99_790, count=99 -> floor(99790/99)=1007
    assert_eq!(
        book.impact_pxs(Ntl(100_000), &mut sink),
        (Some(Px(997)), Some(Px(1007)))
    );
    // Exhausted book returns None
    assert_eq!(book.impact_px(Side::Bid, Ntl(10_000_000), &mut sink), None);
    // Overflow past 0x7fff_ffff_ffff_fffe returns None
    assert_eq!(
        impact_walk_levels([(Px(MAX_IMPACT_NOTIONAL_PRODUCT), Sz(2))], Ntl(10), &mut sink),
        None
    );

    // L2 aggregation: 123456 with n_sig_figs=3 -> bid 123000, ask 124000; n_sig_figs=5, mantissa=5 -> step 50
    assert_eq!(bucket_l2_px(Px(123_456), Side::Bid, 3, None), Px(123_000));
    assert_eq!(bucket_l2_px(Px(123_456), Side::Ask, 3, None), Px(124_000));
    assert_eq!(bucket_l2_px(Px(123_456), Side::Bid, 5, Some(5)), Px(123_450));
    assert_eq!(bucket_l2_px(Px(123_456), Side::Ask, 5, Some(5)), Px(123_500));
    let (agg_bids, agg_asks) = book.l2_snapshot_aggregated(Some(2), None, 10);
    // Bids 1000->1000, 995->990, 990->990 => 2 buckets: (1000, 50) and (990, 300)
    assert_eq!(agg_bids.len(), 2);
    assert_eq!((agg_bids[0].px, agg_bids[0].sz), (Px(1000), Sz(50)));
    assert_eq!((agg_bids[1].px, agg_bids[1].sz, agg_bids[1].n_orders), (Px(990), Sz(300), 2));
    assert!(!agg_asks.is_empty());

    // Order price shaping (`0x5a21510`): Bid 1.1x / Ask 0.9x, tick snap, caps, system user, band gate
    let base_ctx = PriceShapeContext {
        user_blocked: false,
        mark_px: Px(100_000),
        tick: 10,
        available_notional: 500_000_000,
        skip_min_notional: false,
        book_ref_pxs: (0, 0),
        rate_limited: false,
        now_ms: 10_000,
        last_alert_ms: 4_000,
        band_exempt: false,
        band_p: 0.20,
    };
    let shaped_bid = shape_order_price(
        PriceShapeRequest {
            user: user(1),
            side: Side::Bid,
            sz: Sz(200),
            optional_ref: None,
            price_move: PriceMove::ByFraction(0),
        },
        base_ctx,
    )
    .unwrap();
    assert_eq!(shaped_bid.limit_px, Px(110_000));
    assert_eq!(shaped_bid.stop_px, Some(Px(100_000)));

    // Ask 0.9x + 1 tick (`q + 1`)
    let shaped_ask = shape_order_price(
        PriceShapeRequest {
            user: user(1),
            side: Side::Ask,
            sz: Sz(200),
            optional_ref: None,
            price_move: PriceMove::ByFraction(0),
        },
        base_ctx,
    )
    .unwrap();
    assert_eq!(shaped_ask.limit_px, Px(90_010));

    // Exact status words (`0x19c`, `0xde`, `0x6d`, `0x6c`, `0xc8`, `0x78`, `0x63`)
    assert_eq!(
        shape_order_price(
            PriceShapeRequest { user: user(1), side: Side::Bid, sz: Sz(200), optional_ref: None, price_move: PriceMove::ByAmount(0) },
            PriceShapeContext { user_blocked: true, ..base_ctx }
        ).unwrap_err().status_word(),
        0x19c
    );
    assert_eq!(
        shape_order_price(
            PriceShapeRequest { user: user(1), side: Side::Ask, sz: Sz(200), optional_ref: None, price_move: PriceMove::ByAmount(100_000) },
            base_ctx
        ).unwrap_err().status_word(),
        0xde
    );
    assert_eq!(
        shape_order_price(
            PriceShapeRequest { user: user(1), side: Side::Bid, sz: Sz(MAX_SHAPED_NOTIONAL_CAP), optional_ref: None, price_move: PriceMove::ByAmount(0) },
            base_ctx
        ).unwrap_err().status_word(),
        0x6d
    );
    assert_eq!(
        shape_order_price(
            PriceShapeRequest { user: user(1), side: Side::Bid, sz: Sz(10_000), optional_ref: None, price_move: PriceMove::ByAmount(0) },
            base_ctx
        ).unwrap_err().status_word(),
        0x6c
    );
    // Min notional $10 rejected for normal user, allowed for system users `[0xff; 20]` / `[0xee; 20]`
    assert_eq!(
        shape_order_price(
            PriceShapeRequest { user: user(1), side: Side::Bid, sz: Sz(10), optional_ref: None, price_move: PriceMove::ByAmount(0) },
            base_ctx
        ).unwrap_err().status_word(),
        0xc8
    );
    assert!(shape_order_price(
        PriceShapeRequest { user: SYSTEM_USER_FF, side: Side::Bid, sz: Sz(10), optional_ref: None, price_move: PriceMove::ByAmount(0) },
        base_ctx
    ).is_ok());
    assert!(shape_order_price(
        PriceShapeRequest { user: SYSTEM_USER_EE, side: Side::Bid, sz: Sz(10), optional_ref: None, price_move: PriceMove::ByAmount(0) },
        base_ctx
    ).is_ok());
    // Rate limit (`0x78`, alert=true since 10_000 >= 4_000 + 5_000)
    assert_eq!(
        shape_order_price(
            PriceShapeRequest { user: user(1), side: Side::Bid, sz: Sz(200), optional_ref: None, price_move: PriceMove::ByAmount(0) },
            PriceShapeContext { rate_limited: true, ..base_ctx }
        ),
        Err(PriceShapeError::RateLimited { should_alert: true })
    );
    // Price band (`0x63` when band_p = 0.05 < 0.10)
    assert_eq!(
        shape_order_price(
            PriceShapeRequest { user: user(1), side: Side::Bid, sz: Sz(200), optional_ref: None, price_move: PriceMove::ByAmount(0) },
            PriceShapeContext { band_p: 0.05, ..base_ctx }
        ),
        Err(PriceShapeError::PriceBandExceeded { band_pct: 5.0 })
    );
}

#[test]
fn book_not_crossed_invariant_and_books_bounds_closure() {
    let mut books: Books<PerpAsset> = Books::new();
    let mut risk = UnboundedRiskOracle::default();
    let mut sink = NoopOverflowSink;

    let b0 = books.entry_or_default(PerpAsset(0));
    b0.insert_order(order_req(1, user(1), Side::Bid, 99, 10, Tif::Gtc, false), &mut risk, &mut sink)
        .unwrap();
    b0.insert_order(order_req(2, user(2), Side::Ask, 101, 10, Tif::Gtc, false), &mut risk, &mut sink)
        .unwrap();
    assert!(!b0.is_crossed());
    b0.assert_not_crossed();

    // Crossing bid sweeps ask and rests at 102 -> still never crossed (`mod.rs:1153:17`).
    let out = b0
        .insert_order(order_req(3, user(3), Side::Bid, 102, 15, Tif::Gtc, false), &mut risk, &mut sink)
        .unwrap();
    assert_eq!(out.fills.len(), 1);
    assert_eq!(out.status, OrderStatus::Resting { oid: 3, remaining: Sz(5) });
    assert!(!b0.is_crossed());
    b0.assert_not_crossed();

    // Out-of-bounds / unpopulated asset lookup returns None cleanly (`books.rs:14:16`/`19:47`).
    assert!(books.get(&PerpAsset(2)).is_none());
    assert!(books.get_mut(&PerpAsset(99)).is_none());
}

#[test]
fn impact_quote_only_reports_overflow_from_a_level_it_visits() {
    use node115_assets::qtys::{Ntl, OverflowKind};
    use node115_orderbook::matching::MAX_ORDER_CAP;

    let mut book = Book::new();
    let mut risk = UnboundedRiskOracle::default();
    let mut setup = NoopOverflowSink;
    let best = order_req(1, user(1), Side::Ask, 100, 5, Tif::Gtc, false);
    book.insert_order(best, &mut risk, &mut setup).unwrap();

    // Each resting size is admissible. Their sum on the second level overflows once.
    for i in 0..=u64::MAX / MAX_ORDER_CAP {
        let oid = i + 2;
        let mut owner = [0; 20];
        owner[12..].copy_from_slice(&oid.to_be_bytes());
        let req = order_req(oid, owner, Side::Ask, 105, MAX_ORDER_CAP, Tif::Gtc, false);
        book.insert_order(req, &mut risk, &mut setup).unwrap();
    }

    let mut observed = RecordingOverflowSink::default();
    for target in [300, 500] {
        assert_eq!(book.impact_px(Side::Ask, Ntl(target), &mut observed), Some(Px(100)));
        assert!(observed.events.is_empty());
    }
    assert_eq!(book.impact_px(Side::Ask, Ntl(501), &mut observed), None);
    assert_eq!(observed.events, [OverflowKind::UnsignedAdd]);
}
