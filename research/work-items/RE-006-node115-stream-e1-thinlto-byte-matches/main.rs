//! Node #115 Stream E1 (`orderbook`, `assets`, `fees`) ThinLTO + business-logic
//! compiled-byte reference source.
//!
//! Compiled with:
//! `rustc +1.95.0 --edition=2021 -C opt-level=3 -C overflow-checks=yes -C lto=thin -C save-temps`
//!
//! Pure `std`, `#![forbid(unsafe_code)]`, 0 external dependencies.

#![forbid(unsafe_code)]
#![allow(dead_code)]

use core::fmt;
use core::num::NonZeroU64;
use std::collections::VecDeque;

// ---------------------------------------------------------------------------
// 1. Orderbook / Assets / Fees domain types whose `Debug::fmt` implementations
//    match 75 strictly disjoint node #115 `.text` FDEs (29,965 B) under ThinLTO.
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum Side {
    Bid,
    Ask,
}

#[derive(Debug)]
pub enum Tpsl {
    Tp,
    Sl,
}

#[derive(Debug)]
pub enum Tif {
    Alo,
    Ioc,
    Gtc,
    FrontendMarket,
    LiquidationMarket,
}

#[derive(Debug)]
pub enum OrderDescription {
    Limit,
    Market,
    TakeProfitMarket,
    TakeProfitLimit,
    StopMarket,
    StopLimit,
    CloseForVaultWithdrawal,
    SpotDustConversion,
    BoleLiquidation,
    TwapSlice(u64),
    TrailingStopMarket,
}

#[derive(Debug)]
pub struct Cloid(pub u128);

#[derive(Debug)]
pub struct Oid(pub u64);

#[derive(Debug)]
pub struct TwapId(pub u64);

#[derive(Debug)]
pub struct Perp(pub usize);

#[derive(Debug)]
pub struct Spot(pub usize);

#[derive(Debug)]
pub struct Token(pub usize);

#[derive(Debug)]
pub struct Px(pub NonZeroU64);

#[derive(Debug)]
pub struct Sz(pub u64);

#[derive(Debug)]
pub struct User(pub [u8; 20]);

#[derive(Debug)]
pub struct Time(pub u64);

#[derive(Debug)]
pub struct RawMap32(pub [u64; 4]);

#[derive(Debug)]
pub struct SubBuilder {
    pub builder: User,
    pub share: u64,
}

#[derive(Debug)]
pub struct OrderBuilderInfo {
    pub builder: User,
    pub fee_rate: u64,
    pub sub_builders: Vec<SubBuilder>,
}

#[derive(Debug)]
pub struct Relationships {
    pub children: Vec<Oid>,
    pub parent: Option<Oid>,
    pub sibling: Option<Oid>,
}

#[derive(Debug)]
pub struct Trigger {
    pub is_market: bool,
    pub trigger_px: Px,
    pub tpsl: Tpsl,
}

#[derive(Debug)]
pub struct OrderCore {
    pub timestamp: Time,
    pub sz: Option<Sz>,
    pub reduce_only: bool,
    pub relationships: Relationships,
    pub description: OrderDescription,
    pub cloid: Option<[u8; 16]>,
    pub builder: Option<OrderBuilderInfo>,
    pub side: Side,
    pub limit_px: Px,
}

#[derive(Debug)]
pub struct BookOrder {
    pub prev_key: Option<usize>,
    pub next_key: Option<usize>,
    pub is_position_tpsl: bool,
    pub resting_sz: Sz,
    pub orig_sz: Sz,
    pub priority_rate: NonZeroU64,
    pub user: User,
    pub tif: Tif,
    pub core: OrderCore,
    pub oid: Oid,
}

#[derive(Debug)]
pub struct LevelSummary {
    pub sz: Sz,
    pub n_orders: usize,
}

#[derive(Debug)]
pub struct PriorityKey {
    pub priority_rate: u32,
    pub oid: Oid,
}

#[derive(Debug)]
pub struct PriorityDequeEntry {
    pub time: Time,
    pub key: PriorityKey,
}

#[derive(Debug)]
pub struct Level {
    pub first_key: Option<usize>,
    pub last_key: Option<usize>,
    pub priority_key_to_order_key: RawMap32,
    pub priority_deque: VecDeque<PriorityDequeEntry>,
    pub zero_region_front: Option<usize>,
    pub summary: LevelSummary,
}

#[derive(Debug)]
pub struct UserState {
    pub book_order_keys: RawMap32,
    pub reduce_only_oids: VecDeque<u64>,
    pub untriggered_orders: VecDeque<u32>,
}

#[derive(Debug)]
#[repr(C)]
pub struct Half {
    pub levels: u64,
}

#[derive(Debug)]
#[repr(C)]
pub struct CloidTracker {
    pub user_trackers: u64,
}

#[derive(Debug)]
#[repr(C)]
pub struct UserCloidTracker {
    pub oid_to_cloid: [u64; 7],
    pub cloid_to_oid: [u64; 7],
}

#[derive(Debug)]
#[repr(C)]
pub struct TriggerOrder {
    pub core: [u64; 23],
    pub trigger: [u64; 2],
}

// ---------------------------------------------------------------------------
// 2. SpotMeta::sz_to_f64_zero_fast (3 x 133 B = 399 B: 0x269d6a0, 0x50bebc0, 0x57cdae0)
// ---------------------------------------------------------------------------

#[repr(C)]
pub struct SpotInfo {
    pub tokens: [usize; 2],
    pub _pad: [u64; 2],
}

#[repr(C)]
pub struct TokenInfo {
    pub _pad0: [u64; 6],
    pub name: String,
    pub sz_decimals: u8,
    pub wei_decimals: u8,
    pub _pad1: [u8; 6],
    pub spots: Vec<usize>,
    pub _pad2: [u64; 22],
    pub deployer_fee_share: u64,
    pub _pad3: [u64; 7],
}

#[repr(C)]
pub struct SpotMeta {
    pub spot_infos: Vec<SpotInfo>,
    pub token_infos: Vec<TokenInfo>,
}

const POW10: [f64; 256] = {
    let mut a = [1.0f64; 256];
    let mut i = 1;
    while i < 256 {
        a[i] = a[i - 1] * 10.0;
        i += 1;
    }
    a
};

#[inline(never)]
pub fn e1_spot_sz_to_f64_zero_fast(sz: u64, spot: usize, meta: &SpotMeta) -> f64 {
    if sz == 0 {
        return 0.0;
    }
    let base = meta.token_infos.get(meta.spot_infos[spot].tokens[0]).unwrap();
    (sz as f64) / POW10[base.sz_decimals as usize]
}

#[inline(never)]
fn fmt_dyn(x: &dyn fmt::Debug) -> String {
    format!("{:?}", x)
}

fn push3<'a, T: fmt::Debug + 'a>(
    out: &mut Vec<&'a dyn fmt::Debug>,
    r0: &'a T,
    r1: &'a &'a T,
    r2: &'a &'a &'a T,
) {
    out.push(r0);
    out.push(r1);
    out.push(r2);
}

fn main() {
    let nz = NonZeroU64::new(1).unwrap();
    let od = std::hint::black_box(OrderDescription::TwapSlice(7));
    let oc = std::hint::black_box(OrderCore {
        timestamp: Time(1),
        sz: Some(Sz(2)),
        reduce_only: false,
        relationships: Relationships {
            children: Vec::new(),
            parent: None,
            sibling: None,
        },
        description: OrderDescription::Limit,
        cloid: None,
        builder: None,
        side: Side::Bid,
        limit_px: Px(nz),
    });
    let bo = std::hint::black_box(BookOrder {
        prev_key: None,
        next_key: None,
        is_position_tpsl: false,
        resting_sz: Sz(1),
        orig_sz: Sz(1),
        priority_rate: nz,
        user: User([0; 20]),
        tif: Tif::Gtc,
        core: OrderCore {
            timestamp: Time(1),
            sz: Some(Sz(2)),
            reduce_only: false,
            relationships: Relationships {
                children: Vec::new(),
                parent: None,
                sibling: None,
            },
            description: OrderDescription::Limit,
            cloid: None,
            builder: None,
            side: Side::Bid,
            limit_px: Px(nz),
        },
        oid: Oid(1),
    });
    let lv = std::hint::black_box(Level {
        first_key: None,
        last_key: None,
        priority_key_to_order_key: RawMap32([0; 4]),
        priority_deque: VecDeque::new(),
        zero_region_front: None,
        summary: LevelSummary {
            sz: Sz(0),
            n_orders: 0,
        },
    });
    let us = std::hint::black_box(UserState {
        book_order_keys: RawMap32([0; 4]),
        reduce_only_oids: VecDeque::new(),
        untriggered_orders: VecDeque::new(),
    });
    let tr = std::hint::black_box(Trigger {
        is_market: true,
        trigger_px: Px(nz),
        tpsl: Tpsl::Tp,
    });
    let obi = std::hint::black_box(OrderBuilderInfo {
        builder: User([0; 20]),
        fee_rate: 1,
        sub_builders: Vec::new(),
    });
    let sb = std::hint::black_box(SubBuilder {
        builder: User([0; 20]),
        share: 1,
    });
    let rel = std::hint::black_box(Relationships {
        children: Vec::new(),
        parent: None,
        sibling: None,
    });
    let ls = std::hint::black_box(LevelSummary {
        sz: Sz(1),
        n_orders: 2,
    });
    let half = std::hint::black_box(Half { levels: 3 });
    let ct = std::hint::black_box(CloidTracker { user_trackers: 4 });
    let uct = std::hint::black_box(UserCloidTracker {
        oid_to_cloid: [0; 7],
        cloid_to_oid: [0; 7],
    });
    let to = std::hint::black_box(TriggerOrder {
        core: [0; 23],
        trigger: [0; 2],
    });
    let pde = std::hint::black_box(PriorityDequeEntry {
        time: Time(1),
        key: PriorityKey {
            priority_rate: 1,
            oid: Oid(2),
        },
    });
    let pk = std::hint::black_box(PriorityKey {
        priority_rate: 1,
        oid: Oid(2),
    });
    let cl = std::hint::black_box(Cloid(1));
    let oi = std::hint::black_box(Oid(2));
    let tw = std::hint::black_box(TwapId(3));
    let pe = std::hint::black_box(Perp(4));
    let sp = std::hint::black_box(Spot(5));
    let tk = std::hint::black_box(Token(6));

    let (
        od1,
        oc1,
        bo1,
        lv1,
        us1,
        tr1,
        obi1,
        sb1,
        rel1,
        ls1,
        half1,
        ct1,
        uct1,
        to1,
        pde1,
        pk1,
        cl1,
        oi1,
        tw1,
        pe1,
        sp1,
        tk1,
    ) = (
        &od, &oc, &bo, &lv, &us, &tr, &obi, &sb, &rel, &ls, &half, &ct, &uct, &to, &pde, &pk, &cl,
        &oi, &tw, &pe, &sp, &tk,
    );
    let (
        od2,
        oc2,
        bo2,
        lv2,
        us2,
        tr2,
        obi2,
        sb2,
        rel2,
        ls2,
        half2,
        ct2,
        uct2,
        to2,
        pde2,
        pk2,
        cl2,
        oi2,
        tw2,
        pe2,
        sp2,
        tk2,
    ) = (
        &od1, &oc1, &bo1, &lv1, &us1, &tr1, &obi1, &sb1, &rel1, &ls1, &half1, &ct1, &uct1, &to1,
        &pde1, &pk1, &cl1, &oi1, &tw1, &pe1, &sp1, &tk1,
    );

    let mut v: Vec<&dyn fmt::Debug> = Vec::new();
    push3(&mut v, &od, &od1, &od2);
    push3(&mut v, &oc, &oc1, &oc2);
    push3(&mut v, &bo, &bo1, &bo2);
    push3(&mut v, &lv, &lv1, &lv2);
    push3(&mut v, &us, &us1, &us2);
    push3(&mut v, &tr, &tr1, &tr2);
    push3(&mut v, &obi, &obi1, &obi2);
    push3(&mut v, &sb, &sb1, &sb2);
    push3(&mut v, &rel, &rel1, &rel2);
    push3(&mut v, &ls, &ls1, &ls2);
    push3(&mut v, &half, &half1, &half2);
    push3(&mut v, &ct, &ct1, &ct2);
    push3(&mut v, &uct, &uct1, &uct2);
    push3(&mut v, &to, &to1, &to2);
    push3(&mut v, &pde, &pde1, &pde2);
    push3(&mut v, &pk, &pk1, &pk2);
    push3(&mut v, &cl, &cl1, &cl2);
    push3(&mut v, &oi, &oi1, &oi2);
    push3(&mut v, &tw, &tw1, &tw2);
    push3(&mut v, &pe, &pe1, &pe2);
    push3(&mut v, &sp, &sp1, &sp2);
    push3(&mut v, &tk, &tk1, &tk2);
    for x in std::hint::black_box(v) {
        std::hint::black_box(fmt_dyn(x));
    }

    let meta = std::hint::black_box(SpotMeta {
        spot_infos: Vec::new(),
        token_infos: Vec::new(),
    });
    if std::hint::black_box(false) {
        std::hint::black_box(e1_spot_sz_to_f64_zero_fast(
            std::hint::black_box(1),
            std::hint::black_box(0),
            &meta,
        ));
    }
}
