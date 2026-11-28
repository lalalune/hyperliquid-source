//! Node #115 Stream E1 (`orderbook`, `assets`) pure-`std` ThinLTO compiled-byte
//! reference source (13 strictly disjoint pure business-logic FDEs = 3,537 B, 0 non-reloc diffs):
//! - `orderbook` (6 FDEs = 1,998 B):
//!   - `Books::cancel_spot_orders_for_user` (`0x22f2160`, `0x50d7ca0`, `0x50d7de0` — 3 x 318 B)
//!   - `Books::cancel_perp_orders_for_user` (`0x22f2000`, `0x50d7b40`, `0x50d7f20` — 3 x 348 B)
//! - `assets` (7 FDEs = 1,539 B):
//!   - `SpotMeta::sz_from_wire` (`0x29aea00`, `0x593da30` — 2 x 242 B)
//!   - `PerpMeta::px_from_wire` (`0x593d920` — 272 B)
//!   - `qtys::scale_one_minus_frac` (`0x2bde660`, `0x54a70a0` — 2 x 179 B)
//!   - `SpotMeta::usdc_wei_per_base_sz` (`0x3c49360` — 211 B)
//!   - `SpotMeta::pair_unique_quote_tokens` (`0x46dfab0` — 214 B)
//!
//! Compiled with:
//! `rustc +1.95.0 --edition=2021 -C opt-level=3 -C overflow-checks=yes -C lto=thin -C save-temps`
//!
//! Pure `std`, `#![forbid(unsafe_code)]`, 0 external dependencies.

#![forbid(unsafe_code)]
#![allow(dead_code)]

use core::hint::black_box;

// ---------------------------------------------------------------------------
// orderbook: Books::cancel_spot_orders_for_user & cancel_perp_orders_for_user
// ---------------------------------------------------------------------------

#[repr(C)]
pub struct Book288 {
    pub raw: [u64; 36],
}

#[repr(C)]
pub struct BooksVec {
    pub books: Vec<Book288>,
}

#[repr(C)]
pub struct CancelArgs<'a> {
    pub asset: Option<usize>,
    pub books: &'a mut BooksVec,
    pub extra_a: usize,
    pub extra_b: usize,
    pub extra_c: usize,
    pub user: [u8; 20],
    pub flag1: bool,
    pub flag2: bool,
}

#[inline(never)]
fn stub_cancel_book(
    book: &mut Book288,
    mut user: [u8; 20],
    always_true: bool,
    extra_b: usize,
    extra_c: usize,
    flag2: bool,
) {
    user[0] ^= 1;
    black_box((book, user, always_true, extra_b, extra_c, flag2));
}

#[inline(never)]
fn stub_post_cancel(
    extra_a: usize,
    mut user: [u8; 20],
    asset: Option<usize>,
    extra_b: usize,
    extra_c: usize,
) {
    user[0] ^= 2;
    black_box((extra_a, user, asset, extra_b, extra_c));
}

#[inline(never)]
pub fn e1_books_cancel_spot_orders_for_user(args: CancelArgs<'_>) {
    let CancelArgs {
        user,
        asset,
        flag2,
        books,
        flag1,
        extra_a,
        extra_b,
        extra_c,
    } = args;
    match asset {
        Some(a) => {
            let book = books.books.get_mut(a).unwrap();
            stub_cancel_book(book, user, true, extra_b, extra_c, flag2);
        }
        None => {
            for book in &mut books.books {
                stub_cancel_book(book, user, true, extra_b, extra_c, flag2);
            }
        }
    }
    if flag1 {
        stub_post_cancel(extra_a, user, asset, extra_b, extra_c);
    }
}

#[inline(never)]
pub fn e1_books_cancel_perp_orders_for_user(args: CancelArgs<'_>) {
    let CancelArgs {
        user,
        asset,
        flag2,
        books,
        flag1,
        extra_a,
        extra_b,
        extra_c,
    } = args;
    match asset {
        Some(a) => {
            let book = books.books.get_mut(a % 10_000).unwrap();
            stub_cancel_book(book, user, true, extra_b, extra_c, flag2);
        }
        None => {
            for book in &mut books.books {
                stub_cancel_book(book, user, true, extra_b, extra_c, flag2);
            }
        }
    }
    if flag1 {
        stub_post_cancel(extra_a, user, asset, extra_b, extra_c);
    }
}

// ---------------------------------------------------------------------------
// assets: SpotMeta, PerpMeta, qtys
// ---------------------------------------------------------------------------

#[derive(Copy, Clone)]
pub struct Token(pub usize);

#[repr(C)]
pub struct SpotInfo {
    pub tokens: [Token; 2],
    _pad: [u8; 0x10],
}

#[repr(C)]
pub struct TokenInfo {
    _pad0: [u8; 0x48],
    pub sz_decimals: u8,
    pub wei_decimals: u8,
    _pad1: [u8; 6],
    pub spots: Vec<usize>,
    _pad2: [u8; 0x158 - 0x68],
}

#[repr(C)]
pub struct SpotMeta {
    pub spot_infos: Vec<SpotInfo>,
    pub token_infos: Vec<TokenInfo>,
}

#[repr(C)]
pub struct PerpAssetInfo {
    _pad0: [u8; 0x1d],
    pub sz_decimals: u8,
    _pad1: [u8; 2],
}

#[repr(C)]
pub struct PerpMeta {
    pub universe: Vec<PerpAssetInfo>,
    _pad0: [u8; 0x50 - 0x18],
    pub pdi: usize,
}

#[repr(C)]
pub struct PairTokens {
    _pad0: [u8; 0x18],
    pub tok_a: usize,
    _pad1: [u8; 0x18],
    pub tok_b: usize,
}

pub enum QuoteSlot {
    Unique(usize),
    Other(bool),
}

// Node #115 `UserError` has 418 variants (`0..418`), placing `InvalidPx` at `0x0069` (105),
// `InvalidSz` at `0x006a` (106), and `Result::<u64, UserError>::Ok` at `0x01a2` (418).
macro_rules! define_user_error {
    ($($v:ident),* $(,)?) => {
        pub enum UserError {
            $($v,)*
            InvalidInput(&'static str),
            Big([u64; 4]),
            Small(u8),
            T0, T1, T2, T3, T4, T5, T6, T7, T8, T9,
            T10, T11, T12, T13, T14, T15, T16, T17, T18, T19,
            T20, T21, T22, T23, T24, T25, T26, T27, T28, T29,
            T30, T31, T32, T33, T34, T35, T36, T37, T38, T39,
            T40, T41, T42, T43, T44, T45, T46, T47, T48, T49,
            T50, T51, T52, T53, T54, T55, T56, T57, T58, T59,
            T60, T61, T62, T63, T64, T65, T66, T67, T68, T69,
            T70, T71, T72, T73, T74, T75, T76, T77, T78, T79,
            T80, T81, T82, T83, T84, T85, T86, T87, T88, T89,
            T90, T91, T92, T93, T94, T95, T96, T97, T98, T99,
            T100, T101, T102, T103, T104, T105, T106, T107, T108, T109,
            T110, T111, T112, T113, T114, T115, T116, T117, T118, T119,
            T120, T121, T122, T123, T124, T125, T126, T127, T128, T129,
            T130, T131, T132, T133, T134, T135, T136, T137, T138, T139,
            T140, T141, T142, T143, T144, T145, T146, T147, T148, T149,
            T150, T151, T152, T153, T154, T155, T156, T157, T158, T159,
            T160, T161, T162, T163, T164, T165, T166, T167, T168, T169,
            T170, T171, T172, T173, T174, T175, T176,
        }
    };
}

define_user_error!(
    V0, V1, V2, V3, V4, V5, V6, V7, V8, V9,
    V10, V11, V12, V13, V14, V15, V16, V17, V18, V19,
    V20, V21, V22, V23, V24, V25, V26, V27, V28, V29,
    V30, V31, V32, V33, V34, V35, V36, V37, V38, V39,
    V40, V41, V42, V43, V44, V45, V46, V47, V48, V49,
    V50, V51, V52, V53, V54, V55, V56, V57, V58, V59,
    V60, V61, V62, V63, V64, V65, V66, V67, V68, V69,
    V70, V71, V72, V73, V74, V75, V76, V77, V78, V79,
    V80, V81, V82, V83, V84, V85, V86, V87, V88, V89,
    V90, V91, V92, V93, V94, V95, V96, V97, V98, V99,
    V100, V101, V102, V103, V104, InvalidPx, InvalidSz, V107, V108, V109,
    V110, V111, V112, V113, V114, V115, V116, V117, V118, V119,
    V120, V121, V122, V123, V124, V125, V126, V127, V128, V129,
    V130, V131, V132, V133, V134, V135, V136, V137, V138, V139,
    V140, V141, V142, V143, V144, V145, V146, V147, V148, V149,
    V150, V151, V152, V153, V154, V155, V156, V157, V158, V159,
    V160, V161, V162, V163, V164, V165, V166, V167, V168, V169,
    V170, V171, V172, V173, V174, V175, V176, V177, V178, V179,
    V180, V181, V182, V183, V184, V185, V186, V187, V188, V189,
    V190, V191, V192, V193, V194, V195, V196, V197, V198, V199,
    V200, V201, V202, V203, V204, V205, V206, V207, V208, V209,
    V210, V211, V212, V213, V214, V215, V216, V217, V218, V219,
    V220, V221, V222, V223, V224, V225, V226, V227, V228, V229,
    V230, V231, V232, V233, V234, V235, V236, V237,
);

#[inline(always)]
fn unwrap_token(opt: Option<&TokenInfo>) -> &TokenInfo {
    opt.unwrap()
}

#[inline(never)]
pub fn e1_spot_meta_sz_from_wire(
    wire_sz: u64,
    spot: usize,
    meta: &SpotMeta,
) -> Result<u64, UserError> {
    let base = meta.spot_infos[spot].tokens[0];
    let sz_decimals = unwrap_token(meta.token_infos.get(base.0)).sz_decimals;
    let Some(scale) = 8u8
        .checked_sub(sz_decimals)
        .and_then(|d| 10u64.checked_pow(u32::from(d)))
    else {
        return Err(UserError::InvalidSz);
    };
    let rem = wire_sz % scale;
    let q = wire_sz / scale;
    if rem != 0 {
        return Err(UserError::InvalidSz);
    }
    Ok(q)
}

#[inline(never)]
pub fn e1_perp_meta_px_from_wire(
    wire_px: u64,
    asset: usize,
    meta: &PerpMeta,
) -> Result<u64, UserError> {
    let pdi = asset / 10_000;
    let idx = asset % 10_000;
    let info = if pdi == meta.pdi {
        meta.universe.get(idx)
    } else {
        None
    }
    .unwrap();
    let dec = 6u8 - info.sz_decimals;
    let Some(scale) = 8u8
        .checked_sub(dec)
        .and_then(|d| 10u64.checked_pow(u32::from(d)))
    else {
        return Err(UserError::InvalidPx);
    };
    let rem = wire_px % scale;
    let q = wire_px / scale;
    if q == 0 || rem != 0 {
        return Err(UserError::InvalidPx);
    }
    Ok(q)
}

#[inline(never)]
pub fn e1_qtys_scale_one_minus_frac(x: i64, frac: f64) -> i64 {
    let _ = u64::try_from(x).unwrap();
    let mult = 1.0 - frac;
    let v = (x as f64) * mult;
    let min = i64::MIN as f64;
    let max = (i64::MAX as f64).next_down();
    let c = if !v.is_finite() {
        0.0
    } else if v < min || v > max {
        v.clamp(min, max)
    } else {
        v
    };
    c as i64
}

#[inline(never)]
pub fn e1_spot_meta_usdc_wei_per_base_sz(meta: &SpotMeta, token: usize) -> u64 {
    let tokens: &[TokenInfo] = &meta.token_infos;
    let usdc_dec = unwrap_token(tokens.get(0)).wei_decimals;
    let base_dec = unwrap_token(tokens.get(token)).sz_decimals;
    10u64.checked_pow(u32::from(usdc_dec - base_dec)).unwrap()
}

#[inline(never)]
pub fn e1_spot_meta_pair_unique_quote_tokens(
    pair: &PairTokens,
    meta: &SpotMeta,
) -> [QuoteSlot; 2] {
    let ta = pair.tok_a;
    let tokens: &[TokenInfo] = &meta.token_infos;
    let a_info = unwrap_token(tokens.get(ta));
    let a = if a_info.spots.len() == 1 {
        QuoteSlot::Unique(meta.spot_infos[a_info.spots[0]].tokens[1].0)
    } else {
        QuoteSlot::Other(false)
    };
    let b_info = unwrap_token(tokens.get(pair.tok_b));
    let b = if b_info.spots.len() == 1 {
        QuoteSlot::Unique(meta.spot_infos[b_info.spots[0]].tokens[1].0)
    } else {
        QuoteSlot::Other(false)
    };
    [a, b]
}

fn main() {
    let f_spot_cancel: fn(CancelArgs<'_>) = e1_books_cancel_spot_orders_for_user;
    let f_perp_cancel: fn(CancelArgs<'_>) = e1_books_cancel_perp_orders_for_user;
    let f_stub_book: fn(&mut Book288, [u8; 20], bool, usize, usize, bool) = stub_cancel_book;
    let f_stub_post: fn(usize, [u8; 20], Option<usize>, usize, usize) = stub_post_cancel;
    let f_spot_sz: fn(u64, usize, &SpotMeta) -> Result<u64, UserError> = e1_spot_meta_sz_from_wire;
    let f_perp_px: fn(u64, usize, &PerpMeta) -> Result<u64, UserError> = e1_perp_meta_px_from_wire;
    let f_scale: fn(i64, f64) -> i64 = e1_qtys_scale_one_minus_frac;
    let f_wei_sz: fn(&SpotMeta, usize) -> u64 = e1_spot_meta_usdc_wei_per_base_sz;
    let f_pair_q: fn(&PairTokens, &SpotMeta) -> [QuoteSlot; 2] =
        e1_spot_meta_pair_unique_quote_tokens;
    black_box((
        f_spot_cancel,
        f_perp_cancel,
        f_stub_book,
        f_stub_post,
        f_spot_sz,
        f_perp_px,
        f_scale,
        f_wei_sz,
        f_pair_q,
    ));
}
