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
