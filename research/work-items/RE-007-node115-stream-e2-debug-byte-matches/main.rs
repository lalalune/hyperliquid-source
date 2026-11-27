//! Live-compilable pure-std `#![forbid(unsafe_code)]` ThinLTO `Debug`/`Display`
//! byte-match sources for 36 strictly disjoint first-party Stream E2 FDEs (8,901 B)
//! in Linux x86-64 `hl-node` #115.
//!
//! Target binary: `artifacts/node/115/hl-node`, SHA-256
//! `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

#![forbid(unsafe_code)]
#![allow(dead_code, non_camel_case_types)]

use std::fmt::{self, Debug, Display, Formatter};
use std::hint::black_box;
use std::num::{NonZeroU32, NonZeroU64};

// --- 1. Single-field tuple structs (293 B value / 296 B &T) ---
#[derive(Debug)]
struct MarginTableId(usize);
#[derive(Debug)]
struct RawLeverage(NonZeroU32);
#[derive(Debug)]
struct TwapId(u64);
#[derive(Debug)]
struct Oid(u64);
#[derive(Debug)]
struct Nonce(u64);
#[derive(Debug)]
struct Decibps(u64);
#[derive(Debug)]
struct PriorityRate(u64);
#[derive(Debug)]
struct PriorityRateLimit(u64);
#[derive(Debug)]
struct Float(f64);

// --- Opaque field helpers preserving exact size/alignment/niche layout ---
struct Opaque8(u64);
impl Debug for Opaque8 {
    #[inline(never)]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", black_box(self.0))
    }
}
struct Opaque8b(u64);
impl Debug for Opaque8b {
    #[inline(never)]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", black_box(self.0))
    }
}
struct Opaque12([u32; 3]);
impl Debug for Opaque12 {
    #[inline(never)]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", black_box(self.0[0]))
    }
}
struct Opaque12b([u32; 3]);
impl Debug for Opaque12b {
    #[inline(never)]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", black_box(self.0[0]))
    }
}
struct Opaque16([u64; 2]);
impl Debug for Opaque16 {
    #[inline(never)]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", black_box(self.0[0]))
    }
}
struct Opaque16b([u64; 2]);
impl Debug for Opaque16b {
    #[inline(never)]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", black_box(self.0[0]))
    }
}
struct Opaque16Niche(u64, NonZeroU64);
impl Debug for Opaque16Niche {
    #[inline(never)]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", black_box(self.0))
    }
}
struct Opaque20([u8; 20]);
impl Debug for Opaque20 {
    #[inline(never)]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", black_box(self.0[0]))
    }
}
struct Opaque24([u64; 3]);
impl Debug for Opaque24 {
    #[inline(never)]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", black_box(self.0[0]))
    }
}
struct Opaque32([u64; 4]);
impl Debug for Opaque32 {
    #[inline(never)]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", black_box(self.0[0]))
    }
}
struct Opaque32Niche(Vec<u8>, u64);
impl Debug for Opaque32Niche {
    #[inline(never)]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", black_box(self.1))
    }
}
struct Opaque184Niche(NonZeroU64, [u64; 22]); // 0xb8 bytes with niche
impl Debug for Opaque184Niche {
    #[inline(never)]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", black_box(self.0))
    }
}

// --- 2. Risk / Clearinghouse ---
#[derive(Debug)]
struct AdlRequirement {
    user: Opaque20,           // +0x10
    position_index: Opaque16, // +0x00
}

#[derive(Debug)]
struct Liquidatable {
    user: Opaque20,            // +0x18
    position_index: Opaque16,  // +0x00
    margin_available: Opaque8, // +0x10
}

#[derive(Debug)]
enum PositionIndex {
    Cross,
    Isolated { asset: usize },
}

#[derive(Debug)]
struct CumFunding {
    all_time: Opaque8,
    since_open: Opaque8,
    since_change: Opaque8,
}

// --- 3. Vaults ---
#[derive(Debug)]
struct Ownership {
    fraction: Opaque8,
    basis: Opaque8b,
}

mod vaults_mod {
    use super::*;

    #[derive(Debug)]
    pub struct UserState {
        pub ownership: Opaque16,         // +0x00
        pub net_ledger_change: Opaque8,  // +0x10
        pub vault_entry_time: Opaque12,  // +0x18
        pub last_deposit_time: Opaque12b,// +0x24
    }
}

// --- 4. L1-shared ---
#[derive(Debug)]
struct OrderBuilderInfo {
    builder: Opaque20,      // +0x20
    fee_rate: Opaque8,      // +0x18
    sub_builders: Vec<u8>,  // +0x00
}

#[derive(Debug)]
struct SubBuilder {
    builder: Opaque20, // +0x08
    share: Opaque8,    // +0x00
}

// --- 5. Exchange ---
mod exch_mod {
    use super::*;

    #[derive(Debug)]
    pub struct UserState {
        pub book_order_keys: Opaque32,         // +0x40
        pub reduce_only_oids: Opaque32Niche,   // +0x00
        pub untriggered_orders: Opaque32Niche, // +0x20
    }

    pub enum ExchangeKind {
        Exchange,
        Rpc,
        EvmState,
    }

    impl Display for ExchangeKind {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            match self {
                Self::Exchange => f.pad("Exchange"),
                Self::Rpc => f.pad("Rpc"),
                Self::EvmState => f.pad("EvmState"),
            }
        }
    }
}

// --- 6. Action-wire ---
#[derive(Debug)]
enum Tpsl {
    Tp,
    Sl,
}

#[derive(Debug)]
struct TrailingStopOrder {
    activation_px: Opaque8,     // +0xc8
    best_px: Opaque8,           // +0xd0
    core: Opaque184Niche,       // +0x00
    retracement: Opaque16Niche, // +0xb8
}

#[derive(Debug)]
struct TriggerOrder {
    core: Opaque184Niche, // +0x00
    trigger: Opaque16,    // +0xb8
}

#[derive(Debug)]
struct Trigger {
    is_market: bool,     // +0x08
    trigger_px: Opaque8, // +0x00
    tpsl: Tpsl,          // +0x09
}

#[derive(Debug)]
struct Relationships {
    children: Opaque24, // +0x20
    parent: Opaque16,   // +0x00
    sibling: Opaque16b, // +0x10
}

#[inline(never)]
fn force_fmt(v: &dyn Debug) {
    let _ = black_box(format!("{v:?}"));
}

#[inline(never)]
fn force_disp(v: &dyn Display) {
    let _ = black_box(format!("{v}"));
}

fn main() {
    let nz = NonZeroU64::new(1).unwrap();
    let nz32 = NonZeroU32::new(10).unwrap();

    let mt = black_box(MarginTableId(1));
    let rl = black_box(RawLeverage(nz32));
    let tw = black_box(TwapId(2));
    let oi = black_box(Oid(3));
    let nn = black_box(Nonce(4));
    let db = black_box(Decibps(5));
    let pr = black_box(PriorityRate(6));
    let prl = black_box(PriorityRateLimit(7));
    let fl = black_box(Float(1.5));

    let rl_ref = &rl;
    let tw_ref = &tw;
    let oi_ref = &oi;
    let nn_ref = &nn;
    let db_ref = &db;
    let pr_ref = &pr;
    let fl_ref = &fl;

    let adl = black_box(AdlRequirement {
        user: Opaque20([0; 20]),
        position_index: Opaque16([0; 2]),
    });
    let adl_ref = &adl;

    let liq = black_box(Liquidatable {
        user: Opaque20([0; 20]),
        position_index: Opaque16([0; 2]),
        margin_available: Opaque8(0),
    });
    let liq_ref = &liq;
    let liq_ref2 = &liq_ref;

    let pi = black_box(PositionIndex::Isolated { asset: 1 });
    let pi_ref = &pi;

    let cf = black_box(CumFunding {
        all_time: Opaque8(1),
        since_open: Opaque8(2),
        since_change: Opaque8(3),
    });

    let own = black_box(Ownership {
        fraction: Opaque8(1),
        basis: Opaque8b(2),
    });

    let vus = black_box(vaults_mod::UserState {
        ownership: Opaque16([0; 2]),
        net_ledger_change: Opaque8(0),
        vault_entry_time: Opaque12([0; 3]),
        last_deposit_time: Opaque12b([0; 3]),
    });
    let vus_ref = &vus;
    let vus_ref2 = &vus_ref;

    let obi = black_box(OrderBuilderInfo {
        builder: Opaque20([0; 20]),
        fee_rate: Opaque8(1),
        sub_builders: Vec::new(),
    });
    let obi_ref = &obi;

    let sb = black_box(SubBuilder {
        builder: Opaque20([0; 20]),
        share: Opaque8(1),
    });
    let sb_ref = &sb;

    let eus = black_box(exch_mod::UserState {
        book_order_keys: Opaque32([0; 4]),
        reduce_only_oids: Opaque32Niche(Vec::new(), 0),
        untriggered_orders: Opaque32Niche(Vec::new(), 0),
    });
    let eus_ref = &eus;

    let tso = black_box(TrailingStopOrder {
        activation_px: Opaque8(1),
        best_px: Opaque8(2),
        core: Opaque184Niche(nz, [0; 22]),
        retracement: Opaque16Niche(0, nz),
    });
    let tso_ref = &tso;

    let tro = black_box(TriggerOrder {
        core: Opaque184Niche(nz, [0; 22]),
        trigger: Opaque16([0; 2]),
    });
    let tro_ref = &tro;

    let trg = black_box(Trigger {
        is_market: true,
        trigger_px: Opaque8(1),
        tpsl: Tpsl::Tp,
    });
    let trg_ref = &trg;

    let rel = black_box(Relationships {
        children: Opaque24([0; 3]),
        parent: Opaque16([0; 2]),
        sibling: Opaque16b([0; 2]),
    });

    let all: [&dyn Debug; 26] = [
        &mt, &rl, &rl_ref, &tw_ref, &oi_ref, &nn_ref, &db, &db_ref, &pr, &pr_ref, &prl, &fl_ref,
        &adl_ref, &liq_ref2, &pi, &pi_ref, &cf, &own, &vus_ref2, &obi_ref, &sb_ref, &eus_ref,
        &tso_ref, &tro_ref, &trg_ref, &rel,
    ];
    for item in black_box(all) {
        force_fmt(item);
    }

    let eks = [
        black_box(exch_mod::ExchangeKind::Exchange),
        black_box(exch_mod::ExchangeKind::Rpc),
        black_box(exch_mod::ExchangeKind::EvmState),
    ];
    for ek in &eks {
        force_disp(ek);
    }
}
