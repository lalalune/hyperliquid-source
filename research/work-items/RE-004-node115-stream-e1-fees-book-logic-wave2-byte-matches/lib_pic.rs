#![forbid(unsafe_code)]
#![allow(dead_code)]

use core::hint::black_box;
use core::panic::Location;
use std::collections::BTreeSet;

static POW10: [f64; 256] = {
    let mut t = [1.0; 256];
    let mut i = 1;
    let mut v = 10.0;
    while i < 256 {
        t[i] = v;
        v *= 10.0;
        i += 1;
    }
    t
};

// ============================================================================
// 1. fees: Clearinghouse::subaccounts_vlm_sum (0x294bcd0, 163 B)
// ============================================================================
#[repr(C)]
pub struct SubAccount {
    _pad0: [u8; 0x18],
    pub user: [u8; 20],
    _pad1: [u8; 0x40 - 0x2c],
}

#[inline(never)]
fn fold_user_vlm(tracker: *const (), mut user: [u8; 20]) -> u64 {
    user[0] ^= 1;
    black_box((tracker, user));
    black_box(0u64)
}

#[inline(always)]
fn sat_add_bug(a: u64, b: u64) -> u64 {
    match a.checked_add(b) {
        Some(v) => v,
        None => {
            e1_stubs::bug_log(0, Location::caller());
            a.saturating_add(b)
        }
    }
}

#[inline(never)]
pub fn e1_fees_subaccounts_vlm_sum(
    subs: Option<&Vec<SubAccount>>,
    acc: u64,
    ctx: &*const (),
) -> u64 {
    let Some(list) = subs else {
        return acc;
    };
    let tracker = *ctx;
    list.iter().fold(acc, |a, sub| {
        let v = fold_user_vlm(tracker, sub.user);
        sat_add_bug(v, a)
    })
}

// ============================================================================
// 2. assets: SpotMeta::mid_px_to_f64 (3 x 239 B: 0x2cac7d0, 0x56449a0, 0x5644a90)
// ============================================================================
#[derive(Copy, Clone)]
pub struct Token(pub usize);

#[repr(C)]
pub struct SpotInfo {
    pub tokens: [Token; 2],
    _pad: [u8; 0x10],
}

#[repr(C)]
pub struct TokenInfoSimple {
    _pad0: [u8; 0x30],
    pub name: String,
    pub sz_decimals: u8,
    pub wei_decimals: u8,
    _pad1: [u8; 6],
    pub spots: Vec<usize>,
    _pad2: [u8; 0x158 - 0x68],
}

#[repr(C)]
pub struct SpotMeta {
    pub spot_infos: Vec<SpotInfo>,
    pub token_infos: Vec<TokenInfoSimple>,
}

#[inline(always)]
fn unwrap_token(opt: Option<&TokenInfoSimple>) -> &TokenInfoSimple {
    opt.unwrap()
}

#[repr(C)]
pub struct ExchangeSpotMidA {
    _pad0: [u8; 0x80],
    pub meta_hdr: [u8; 0x10],
    pub meta: SpotMeta,
    _pad1: [u8; 0x3ad8 - 0xc0],
    pub spot_books: [u64; 4],
}

#[repr(C)]
pub struct ExchangeSpotMidB {
    _pad0: [u8; 0x80],
    pub meta_hdr: [u8; 0x10],
    pub meta: SpotMeta,
    _pad1: [u8; 0x4648 - 0xc0],
    pub spot_books: [u64; 4],
}

#[inline(never)]
pub fn e1_assets_mid_px_to_f64_a(kind: usize, spot: usize, exch: &ExchangeSpotMidA) -> f64 {
    if kind != 1 {
        return 2.0;
    }
    let raw = e1_stubs::fetch_mid_raw(&exch.meta_hdr, spot, &exch.spot_books);
    let spot_info = &exch.meta.spot_infos[spot];
    let tokens: &[TokenInfoSimple] = &exch.meta.token_infos;
    let [base, quote] = spot_info.tokens;
    let dec = unwrap_token(tokens.get(quote.0)).wei_decimals
        - unwrap_token(tokens.get(base.0)).sz_decimals;
    (raw as f64) / POW10[usize::from(dec)]
}

#[inline(never)]
pub fn e1_assets_mid_px_to_f64_b(kind: usize, spot: usize, exch: &ExchangeSpotMidB) -> f64 {
    if kind != 1 {
        return 2.0;
    }
    let raw = e1_stubs::fetch_mid_raw(&exch.meta_hdr, spot, &exch.spot_books);
    let spot_info = &exch.meta.spot_infos[spot];
    let tokens: &[TokenInfoSimple] = &exch.meta.token_infos;
    let [base, quote] = spot_info.tokens;
    let dec = unwrap_token(tokens.get(quote.0)).wei_decimals
        - unwrap_token(tokens.get(base.0)).sz_decimals;
    (raw as f64) / POW10[usize::from(dec)]
}

// ============================================================================
// 3. assets: SpotMeta::is_user_frozen (0x3c49440, 255 B)
// ============================================================================
#[repr(C, u32)]
pub enum FreezeState {
    NotFreezeable = 0,
    Freezeable(BTreeSet<[u8; 20]>) = 1,
}

#[repr(C)]
pub struct TokenInfoFreeze {
    _pad0: [u8; 0x10],
    pub freeze: FreezeState,
    _pad1: [u8; 0x158 - 0x30],
}

#[repr(C)]
pub struct SpotMetaFreeze {
    pub spot_infos: Vec<SpotInfo>,
    pub token_infos: Vec<TokenInfoFreeze>,
}

#[inline(never)]
pub fn e1_assets_is_user_frozen(meta: &SpotMetaFreeze, user: &[u8; 20], token: usize) -> bool {
    match &meta.token_infos.get(token).unwrap().freeze {
        FreezeState::Freezeable(set) => set.contains(user),
        FreezeState::NotFreezeable => false,
    }
}

// ============================================================================
// 4. assets: SpotClearinghouse::capped_usdc_ntl (0x3bfa270, 200 B)
// ============================================================================
#[repr(C)]
pub struct SpotClearinghouse {
    _pad0: [u8; 0x10],
    pub meta: SpotMeta,
}

#[inline(never)]
pub fn e1_assets_capped_usdc_ntl(
    sc: &SpotClearinghouse,
    token: usize,
    wei: u64,
    extra: usize,
) -> u64 {
    if token == 0 {
        return wei / 100;
    }
    let px = e1_stubs::spot_mark_px((sc as *const SpotClearinghouse).cast(), token, extra);
    if px == 0 {
        return 0;
    }
    let res = e1_stubs::wei_to_usdc_ntl(
        wei,
        token,
        px,
        false,
        (&sc.meta as *const SpotMeta).cast(),
    )
    .unwrap_or(0);
    if token != 1 && unwrap_token(sc.meta.token_infos.get(token)).name != "HYPE" {
        res.min(10_000_000_000_000_000)
    } else {
        res
    }
}

// ============================================================================
// 5. assets: qtys::net_balance (0x4215880, 190 B)
// ============================================================================
#[repr(C)]
pub struct BalanceState {
    pub hold: i64,
    pub total: i64,
    _pad: [u64; 3],
    pub extra: i64,
}

#[inline(always)]
fn to_nonneg_u64(x: i64) -> u64 {
    u64::try_from(x).unwrap()
}

#[inline(never)]
pub fn e1_assets_net_balance(bal: &BalanceState, user: &[u8; 20]) -> i64 {
    let total = to_nonneg_u64(bal.total);
    let hold = to_nonneg_u64(bal.hold);
    let diff = (total as i64).wrapping_sub(hold as i64);
    if *user == [0xbb; 20] {
        let extra = to_nonneg_u64(bal.extra) as i64;
        match diff.checked_add(extra) {
            Some(v) => v,
            None => {
                e1_stubs::bug_log(0, Location::caller());
                diff.saturating_add(extra)
            }
        }
    } else {
        diff
    }
}
