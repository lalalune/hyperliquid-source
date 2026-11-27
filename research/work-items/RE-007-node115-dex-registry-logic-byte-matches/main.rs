#![forbid(unsafe_code)]
#![allow(dead_code)]
//! Independently authored node #115 `dex-registry` (`l1/src/dex_registry/{perp_dex,clearinghouses}.rs`)
//! pure business-logic functions for live compiled-byte identity verification with
//! `rustc 1.95.0 (59807616e 2026-04-14)`
//! (`--edition=2021 --crate-type=bin -C opt-level=3 -C overflow-checks=yes -C relocation-model=pie -C codegen-units=1`).
//!
//! Reproduces 31 strictly disjoint `.text` FDE windows (5,124 B total) in `dex-registry`:
//! - `PerpDexes::get` / `get_mut` (`0x4201750`, `0x42017d0`; 2 x 113 B)
//! - `Clearinghouses::get` / `get_mut` (`0x446b2f0`, `0x446b370`, `0x446b3f0`; 3 x 113 B)
//! - `Clearinghouses::get_by_asset` (`0x276d060`, `0x5b00e50`, `0x5b00ee0`; 3 x 133 B)
//! - `Exchange::clearinghouse_by_asset` (`0x2753a70`, `0x5aed6d0`, `0x2a8b2e0`, `0x2a8b370`,
//!   `0x55e93a0`, `0x5aed760`, `0x55e9310`; 7 x 139 B)
//! - `Exchange::perp_dex_by_asset` (`0x5aed7f0`, `0x2753b00`, `0x5aed880`; 3 x 139 B)
//! - `Exchange::perp_book_by_asset` (`0x5aee050`, `0x2753ed0`, `0x5aedf90`, `0x276e0d0`,
//!   `0x5b03a10`, `0x276e000`, `0x5b03ae0`, `0x276e1a0`; 3 x 192 B + 5 x 198 B)
//! - `Exchange::perp_book_summary` (`0x2753750`, `0x5aed180`, `0x5aed090`; 3 x 232 B)
//! - `Clearinghouses::get_by_name` / `get_mut_by_name` (`0x446af70`, `0x446b070`; 2 x 254 B)

/// Minimal 0x70-byte, 16-byte-aligned L1 error envelope carrying the node #115
/// `UnknownPdi` discriminant (`0x156`) and an unwinding `Drop` glue call.
#[repr(u16)]
#[derive(Debug)]
enum L1Err {
    Pad([u128; 6]) = 0,
    UnknownPdi = 0x156,
    Ok = 0x1a2,
}

#[inline(never)]
fn opaque_may_unwind(p: &mut L1Err) {
    if core::hint::black_box(p as *mut L1Err as usize) == 1 {
        panic!("drop");
    }
}

impl Drop for L1Err {
    #[inline(never)]
    fn drop(&mut self) {
        opaque_may_unwind(self);
    }
}

#[repr(C)]
pub struct BookEntry {
    _pad0: [u8; 0xa8],
    pub inner: [u8; 0x120 - 0xa8],
}

#[repr(C)]
pub struct PerpDex {
    pub books: Vec<BookEntry>,
    _pad: [u8; 0x200 - 24],
}

#[repr(C)]
pub struct Hip3SchemaName {
    pub name: String,
}

#[repr(C)]
pub struct Clearinghouse {
    _pad0: [u8; 0x378],
    pub kind_niche: i64,
    _pad1: [u8; 0x4a0 - 0x380],
    pub schema: Box<Hip3SchemaName>,
    _pad2: [u8; 0x510 - 0x4a8],
}

#[repr(C)]
pub struct PerpDexes(pub Vec<PerpDex>);

#[repr(C)]
pub struct Clearinghouses(pub Vec<Clearinghouse>);

#[repr(C)]
pub struct ExchangeCh7c0 {
    _pad: [u8; 0x7c0],
    pub chs: Vec<Clearinghouse>,
}

#[repr(C)]
pub struct ExchangeCh1330 {
    _pad: [u8; 0x1330],
    pub chs: Vec<Clearinghouse>,
}

#[repr(C)]
pub struct ExchangePerp1fa0 {
    _pad: [u8; 0x1fa0],
    pub pds: Vec<PerpDex>,
}

#[repr(C)]
pub struct ExchangePerp3ac0 {
    _pad: [u8; 0x3ac0],
    pub pds: Vec<PerpDex>,
}

#[repr(C)]
pub struct ExchangePerp4630 {
    _pad: [u8; 0x4630],
    pub pds: Vec<PerpDex>,
}

#[repr(u16)]
pub enum LookupRes<'a> {
    Pad([u128; 6]) = 0,
    UnknownPdi = 0x156,
    Ok(&'a Clearinghouse) = 0x1a2,
}

#[inline(never)]
fn book_summary_helper(inner: &[u8; 0x120 - 0xa8], book: &BookEntry) -> [u64; 4] {
    core::hint::black_box((inner, book));
    [0; 4]
}

// ---------------------------------------------------------------------------
// 1. Direct Pdi indexers (113 B each: 5 FDEs)
// ---------------------------------------------------------------------------

#[inline(never)]
pub fn dex_perp_dexes_get_113(s: &PerpDexes, pdi: usize) -> &PerpDex {
    s.0.get(pdi).ok_or(L1Err::UnknownPdi).unwrap()
}

#[inline(never)]
pub fn dex_clearinghouses_get_113(s: &Clearinghouses, pdi: usize) -> &Clearinghouse {
    s.0.get(pdi).ok_or(L1Err::UnknownPdi).unwrap()
}

// ---------------------------------------------------------------------------
// 2. Asset-ID (`asset / 10_000`) Clearinghouses indexer (133 B each: 3 FDEs)
// ---------------------------------------------------------------------------

#[inline(never)]
pub fn dex_clearinghouses_by_asset_133(asset: usize, s: &Clearinghouses) -> &Clearinghouse {
    s.0.get(asset / 10_000).ok_or(L1Err::UnknownPdi).unwrap()
}

// ---------------------------------------------------------------------------
// 3. Exchange-embedded asset-ID indexers (139 B each: 10 FDEs)
// ---------------------------------------------------------------------------

#[inline(never)]
pub fn dex_ex_ch7c0_asset_139(asset: usize, ex: &ExchangeCh7c0) -> &Clearinghouse {
    ex.chs.get(asset / 10_000).ok_or(L1Err::UnknownPdi).unwrap()
}

#[inline(never)]
pub fn dex_ex_ch7c0_rev_139(ex: &ExchangeCh7c0, asset: usize) -> &Clearinghouse {
    ex.chs.get(asset / 10_000).ok_or(L1Err::UnknownPdi).unwrap()
}

#[inline(never)]
pub fn dex_ex_ch1330_asset_139(asset: usize, ex: &ExchangeCh1330) -> &Clearinghouse {
    ex.chs.get(asset / 10_000).ok_or(L1Err::UnknownPdi).unwrap()
}

#[inline(never)]
pub fn dex_ex_ch1330_rev_139(ex: &ExchangeCh1330, asset: usize) -> &Clearinghouse {
    ex.chs.get(asset / 10_000).ok_or(L1Err::UnknownPdi).unwrap()
}

#[inline(never)]
pub fn dex_ex_perp4630_asset_139(asset: usize, ex: &ExchangePerp4630) -> &PerpDex {
    ex.pds.get(asset / 10_000).ok_or(L1Err::UnknownPdi).unwrap()
}

#[inline(never)]
pub fn dex_ex_perp3ac0_asset_139(asset: usize, ex: &ExchangePerp3ac0) -> &PerpDex {
    ex.pds.get(asset / 10_000).ok_or(L1Err::UnknownPdi).unwrap()
}

// ---------------------------------------------------------------------------
// 4. Two-level `(pdi, local)` PerpDex book indexers (192 B x 3 + 198 B x 5)
// ---------------------------------------------------------------------------

#[inline(never)]
pub fn dex_ex_perp4630_book_get_192(asset: usize, ex: &ExchangePerp4630) -> &BookEntry {
    let pdi = asset / 10_000;
    let local = asset % 10_000;
    ex.pds
        .get(pdi)
        .ok_or(L1Err::UnknownPdi)
        .unwrap()
        .books
        .get(local)
        .unwrap()
}

#[inline(never)]
pub fn dex_ex_perp3ac0_book_get_192(asset: usize, ex: &ExchangePerp3ac0) -> &BookEntry {
    let pdi = asset / 10_000;
    let local = asset % 10_000;
    ex.pds
        .get(pdi)
        .ok_or(L1Err::UnknownPdi)
        .unwrap()
        .books
        .get(local)
        .unwrap()
}

#[inline(never)]
pub fn dex_ex_perp4630_book_idx_198(asset: usize, ex: &ExchangePerp4630) -> &BookEntry {
    let pdi = asset / 10_000;
    let local = asset % 10_000;
    &ex.pds.get(pdi).ok_or(L1Err::UnknownPdi).unwrap().books[local]
}

#[inline(never)]
pub fn dex_ex_perp3ac0_book_idx_198(asset: usize, ex: &ExchangePerp3ac0) -> &BookEntry {
    let pdi = asset / 10_000;
    let local = asset % 10_000;
    &ex.pds.get(pdi).ok_or(L1Err::UnknownPdi).unwrap().books[local]
}

#[inline(never)]
pub fn dex_ex_perp1fa0_book_idx_198(asset: usize, ex: &ExchangePerp1fa0) -> &BookEntry {
    let pdi = asset / 10_000;
    let local = asset % 10_000;
    &ex.pds.get(pdi).ok_or(L1Err::UnknownPdi).unwrap().books[local]
}

// ---------------------------------------------------------------------------
// 5. Two-level PerpDex book summary helpers (232 B x 3)
// ---------------------------------------------------------------------------

#[inline(never)]
pub fn dex_ex_perp3ac0_book_summary_232(
    _unused: usize,
    asset: usize,
    ex: &ExchangePerp3ac0,
) -> [u64; 4] {
    let pdi = asset / 10_000;
    let local = asset % 10_000;
    let book = &ex.pds.get(pdi).ok_or(L1Err::UnknownPdi).unwrap().books[local];
    book_summary_helper(&book.inner, book)
}

#[inline(never)]
pub fn dex_ex_perp4630_book_summary_232(
    _unused: usize,
    asset: usize,
    ex: &ExchangePerp4630,
) -> [u64; 4] {
    let pdi = asset / 10_000;
    let local = asset % 10_000;
    let book = &ex.pds.get(pdi).ok_or(L1Err::UnknownPdi).unwrap().books[local];
    book_summary_helper(&book.inner, book)
}

// ---------------------------------------------------------------------------
// 6. Clearinghouses::get_by_name / get_mut_by_name (254 B x 2)
// ---------------------------------------------------------------------------

#[inline(never)]
pub fn dex_clearinghouses_get_by_name_254<'a>(
    chs: &'a Clearinghouses,
    name: &str,
) -> LookupRes<'a> {
    if name.is_empty() {
        return LookupRes::Ok(chs.0.get(0).ok_or(L1Err::UnknownPdi).unwrap());
    }
    for ch in &chs.0 {
        if 0i64.overflowing_sub(ch.kind_niche).1 {
            continue;
        }
        if ch.schema.name == name {
            return LookupRes::Ok(ch);
        }
    }
    LookupRes::UnknownPdi
}

fn main() {
    core::hint::black_box(dex_perp_dexes_get_113 as *const () as usize);
    core::hint::black_box(dex_clearinghouses_get_113 as *const () as usize);
    core::hint::black_box(dex_clearinghouses_by_asset_133 as *const () as usize);
    core::hint::black_box(dex_ex_ch7c0_asset_139 as *const () as usize);
    core::hint::black_box(dex_ex_ch7c0_rev_139 as *const () as usize);
    core::hint::black_box(dex_ex_ch1330_asset_139 as *const () as usize);
    core::hint::black_box(dex_ex_ch1330_rev_139 as *const () as usize);
    core::hint::black_box(dex_ex_perp4630_asset_139 as *const () as usize);
    core::hint::black_box(dex_ex_perp3ac0_asset_139 as *const () as usize);
    core::hint::black_box(dex_ex_perp4630_book_get_192 as *const () as usize);
    core::hint::black_box(dex_ex_perp3ac0_book_get_192 as *const () as usize);
    core::hint::black_box(dex_ex_perp4630_book_idx_198 as *const () as usize);
    core::hint::black_box(dex_ex_perp3ac0_book_idx_198 as *const () as usize);
    core::hint::black_box(dex_ex_perp1fa0_book_idx_198 as *const () as usize);
    core::hint::black_box(dex_ex_perp3ac0_book_summary_232 as *const () as usize);
    core::hint::black_box(dex_ex_perp4630_book_summary_232 as *const () as usize);
    core::hint::black_box(dex_clearinghouses_get_by_name_254 as *const () as usize);
}
