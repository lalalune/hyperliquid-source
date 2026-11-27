#![forbid(unsafe_code)]
#![allow(dead_code)]
//! Independently authored Stream E2 node #115 non-visitor business-logic first-party
//! Rust functions for compiled-byte identity verification with
//! `rustc 1.95.0 (59807616e 2026-04-14)`
//! (`--edition=2021 --crate-type=rlib -C opt-level=3 -C overflow-checks=yes`).
//!
//! Covers 16 strictly disjoint `.text` FDE windows (4,645 B total) across 4 Stream E2
//! components (`exchange`, `action-wire`, `l1-shared`, `risk`):
//! - `exchange` Bole Reserve fixed-point utilization math (`0x36a08b0` 312 B, `0x36a09f0` 309 B)
//! - `exchange` 18-variant compact Exchange/Clearinghouse JSON `visit_str` (`0x286d0c0`, `0x4682fd0`)
//! - `exchange` `UserAbstraction` 11-alias JSON `visit_str` (`0x23c5330`, `0x3bdd050`)
//! - `exchange` `BoleReserve` 9-field compact JSON `visit_str` (`0x288f7f0`, `0x4699090`)
//! - `action-wire` `OrderKind` 22-alias JSON `visit_str` (`0x25d03a0`, `0x4450a20`)
//! - `l1-shared` `NodeRole` 4-variant JSON `visit_str` (`0x1543ce0`, `0x57c3c90`) & `Display::fmt` (`0x1553730`)
//! - `risk` 9-tag compact `visit_str` (`0x2886380`, `0x4693600`) & `OracleKind::fmt` (`0x3d66320`)

use core::fmt;

// ---------------------------------------------------------------------------
// 1. Bole Reserve pure fixed-point u128 utilization math (0x36a08b0, 0x36a09f0)
// ---------------------------------------------------------------------------

#[repr(C)]
pub struct BoleReserveLayout {
    _pad0: [u64; 8],
    pub borrow_shares: u64, // 0x40
    _pad1: [u64; 2],
    pub borrow_index: u64,  // 0x58
    pub supply_shares: u64, // 0x60
    _pad2: [u64; 2],
    pub supply_index: u64,  // 0x78
}

#[derive(Copy, Clone)]
pub enum BoleMathErr {
    E0,
    E1,
    Zero,
    Overflow,
}

pub enum BoleReserveErr {
    E0,
    E1,
    Zero,
    Overflow,
    Payload([u8; 24]),
}

impl From<BoleMathErr> for BoleReserveErr {
    #[inline(always)]
    fn from(e: BoleMathErr) -> Self {
        match e {
            BoleMathErr::E0 => BoleReserveErr::E0,
            BoleMathErr::E1 => BoleReserveErr::E1,
            BoleMathErr::Zero => BoleReserveErr::Zero,
            BoleMathErr::Overflow => BoleReserveErr::Overflow,
        }
    }
}

#[inline(always)]
fn shares_to_wei(shares: u64, index: u64, round_up: bool) -> Result<u64, BoleMathErr> {
    let scale = 100_000_000_000_000u128;
    let prod = (shares as u128) * (index as u128);
    let q = if round_up {
        prod.div_ceil(scale)
    } else {
        prod / scale
    };
    let out = u64::try_from(q).map_err(|_| BoleMathErr::Overflow)?;
    if shares == 0 && out != 0 {
        return Err(BoleMathErr::Zero);
    }
    Ok(out)
}

#[inline(always)]
fn utilization_scaled_inner(r: &BoleReserveLayout) -> Result<u64, BoleMathErr> {
    let b = shares_to_wei(r.borrow_shares, r.borrow_index, true);
    let s = shares_to_wei(r.supply_shares, r.supply_index, false);
    let (b, s) = (b?, s?);
    if s == 0 {
        return Ok(0);
    }
    let u = u64::try_from((b as u128 * 100_000_000_000_000u128) / (s as u128))
        .map_err(|_| BoleMathErr::Overflow)?;
    Ok(u.min(100_000_000_000_000))
}

/// `exchange`: `BoleReserve::utilization_bps` (`0x36a08b0..0x36a09e8`, 312 B).
#[inline(never)]
pub fn exchange_bole_reserve_utilization_bps(r: &BoleReserveLayout) -> Result<u64, BoleReserveErr> {
    Ok(utilization_scaled_inner(r)? / 10_000_000_000)
}

/// `exchange`: `BoleReserve::utilization_f64` (`0x36a09f0..0x36a0b25`, 309 B).
#[inline(never)]
pub fn exchange_bole_reserve_utilization_f64(r: &BoleReserveLayout) -> Result<f64, BoleReserveErr> {
    Ok((utilization_scaled_inner(r)? as f64) / 100_000_000_000_000.0)
}

// ---------------------------------------------------------------------------
// 2. Display::fmt business-logic enum formatters (0x1553730, 0x3d66320)
// ---------------------------------------------------------------------------

#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum NodeRole {
    BridgeVoter = 0,
    ReferenceOraclePublisher = 1,
    OutcomeVoter = 2,
    Visor = 3,
}

/// `l1-shared`: `NodeRole::fmt` (`0x1553730..0x155379a`, 106 B).
#[inline(never)]
pub fn l1_shared_node_role_fmt_display(r: &NodeRole, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match r {
        NodeRole::BridgeVoter => f.write_str("bridge-voter"),
        NodeRole::ReferenceOraclePublisher => f.write_str("reference-oracle-publisher"),
        NodeRole::OutcomeVoter => f.write_str("outcome-voter"),
        NodeRole::Visor => f.write_str("visor"),
    }
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum OracleKind {
    Spot = 0,
    Mark = 1,
    ExternalPerp = 2,
}

/// `risk`: `OracleKind::fmt` (`0x3d66320..0x3d6636e`, 78 B).
#[inline(never)]
pub fn risk_oracle_kind_fmt_display(k: &OracleKind, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match k {
        OracleKind::Spot => f.write_str("Spot"),
        OracleKind::Mark => f.write_str("Mark"),
        OracleKind::ExternalPerp => f.write_str("ExternalPerp"),
    }
}

// ---------------------------------------------------------------------------
// 3. Stream E2 JSON enum/field visit_str dispatchers (12 FDEs, 3,840 B)
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq)]
pub struct JsonErr(pub Box<[usize; 2]>);

#[cold]
#[inline(never)]
fn json_unknown_variant(v: &str, expected: &'static [&'static str]) -> JsonErr {
    let p = core::hint::black_box((v.as_ptr(), v.len(), expected.as_ptr(), expected.len()));
    JsonErr(Box::new([(p.0 as usize) ^ p.1, (p.2 as usize) ^ p.3]))
}

pub fn retain_json_unknown_variant(v: &str) -> JsonErr {
    json_unknown_variant(v, &[])
}

/// `action-wire`: `OrderKind` 22-alias JSON `visit_str`
/// (`0x25d03a0..0x25d05eb` & `0x4450a20..0x4450c6b`, 587 B each).
#[inline(never)]
pub fn action_wire_order_kind_22_visit_str(v: &str) -> Result<u8, JsonErr> {
    const VARIANTS: &[&str] = &[
        "l", "limit",
        "m", "market",
        "T", "takeProfitMarket",
        "t", "takeProfitLimit",
        "S", "stopMarket",
        "s", "stopLimit",
        "closeForVaultWithdrawal", "v",
        "d", "spotDustConversion",
        "b", "borrowLendLiquidation",
        "twapSlice", "w",
        "trailingStopMarket", "z",
    ];
    match v {
        "l" => Ok(0),
        "m" => Ok(1),
        "T" => Ok(2),
        "t" => Ok(3),
        "S" => Ok(4),
        "s" => Ok(5),
        "v" => Ok(6),
        "d" => Ok(7),
        "b" => Ok(8),
        "w" => Ok(9),
        "z" => Ok(10),
        "limit" => Ok(0),
        "market" => Ok(1),
        "takeProfitMarket" => Ok(2),
        "takeProfitLimit" => Ok(3),
        "stopMarket" => Ok(4),
        "stopLimit" => Ok(5),
        "closeForVaultWithdrawal" => Ok(6),
        "spotDustConversion" => Ok(7),
        "borrowLendLiquidation" => Ok(8),
        "twapSlice" => Ok(9),
        "trailingStopMarket" => Ok(10),
        _ => Err(json_unknown_variant(v, VARIANTS)),
    }
}

/// `exchange`: 18-variant compact Exchange/Clearinghouse/ADL/PM field JSON `visit_str`
/// (`0x286d0c0..0x286d2a0` & `0x4682fd0..0x46831b0`, 480 B each).
#[inline(never)]
pub fn exchange_compact_18_visit_str(v: &str) -> Result<u8, JsonErr> {
    const VARIANTS: &[&str] = &[
        "e", "r", "b", "btp", "P", "Ps", "mu", "f", "t",
        "dp", "du", "pmv", "pma", "pmu", "rl", "mbs", "adl", "ri",
    ];
    match v {
        "e" => Ok(0),
        "r" => Ok(1),
        "b" => Ok(2),
        "P" => Ok(4),
        "f" => Ok(7),
        "t" => Ok(8),
        "Ps" => Ok(5),
        "mu" => Ok(6),
        "dp" => Ok(9),
        "du" => Ok(10),
        "rl" => Ok(14),
        "ri" => Ok(17),
        "btp" => Ok(3),
        "pmv" => Ok(11),
        "pma" => Ok(12),
        "pmu" => Ok(13),
        "mbs" => Ok(15),
        "adl" => Ok(16),
        _ => Err(json_unknown_variant(v, VARIANTS)),
    }
}

/// `exchange`: `UserAbstraction` 11-alias JSON `visit_str`
/// (`0x23c5330..0x23c544d` & `0x3bdd050..0x3bdd16d`, 285 B each).
#[inline(never)]
pub fn exchange_user_abstraction_11_visit_str(v: &str) -> Result<u8, JsonErr> {
    const VARIANTS: &[&str] = &[
        "d", "default", "dexAbstraction",
        "e", "disabled",
        "i", "z",
        "u", "unifiedAccount",
        "p", "portfolioMargin",
    ];
    match v {
        "d" => Ok(0),
        "e" => Ok(0),
        "i" => Ok(1),
        "z" => Ok(2),
        "u" => Ok(3),
        "p" => Ok(4),
        "default" => Ok(0),
        "dexAbstraction" => Ok(0),
        "disabled" => Ok(1),
        "unifiedAccount" => Ok(3),
        "portfolioMargin" => Ok(4),
        _ => Err(json_unknown_variant(v, VARIANTS)),
    }
}

/// `l1-shared`: `NodeRole` 4-variant JSON `visit_str`
/// (`0x1543ce0..0x1543dca` & `0x57c3c90..0x57c3d7a`, 234 B each).
#[inline(never)]
pub fn l1_shared_node_role_4_visit_str(v: &str) -> Result<u8, JsonErr> {
    const VARIANTS: &[&str] = &[
        "bridge-voter",
        "reference-oracle-publisher",
        "outcome-voter",
        "visor",
    ];
    match v {
        "bridge-voter" => Ok(0),
        "reference-oracle-publisher" => Ok(1),
        "outcome-voter" => Ok(2),
        "visor" => Ok(3),
        _ => Err(json_unknown_variant(v, VARIANTS)),
    }
}

/// `exchange`: `BoleReserve` 9-field compact JSON `visit_str`
/// (`0x288f7f0..0x288f8b5` & `0x4699090..0x4699155`, 197 B each).
#[inline(never)]
pub fn exchange_bole_reserve_9_visit_str(v: &str) -> Result<u8, JsonErr> {
    const VARIANTS: &[&str] = &["t", "l", "y", "b", "s", "ub", "us", "Mp", "mp"];
    match v {
        "t" => Ok(0),
        "l" => Ok(1),
        "y" => Ok(2),
        "b" => Ok(3),
        "s" => Ok(4),
        "ub" => Ok(5),
        "us" => Ok(6),
        "Mp" => Ok(7),
        "mp" => Ok(8),
        _ => Err(json_unknown_variant(v, VARIANTS)),
    }
}

/// `risk`: 9-tag compact Clearinghouse/Bole JSON `visit_str`
/// (`0x2886380..0x2886409` & `0x4693600..0x4693689`, 137 B each).
#[inline(never)]
pub fn risk_compact_9_visit_str(v: &str) -> Result<u8, JsonErr> {
    const VARIANTS: &[&str] = &["d", "D", "r", "w", "e", "b", "m", "a", "A"];
    match v {
        "d" => Ok(0),
        "D" => Ok(1),
        "r" => Ok(2),
        "w" => Ok(3),
        "e" => Ok(4),
        "b" => Ok(5),
        "m" => Ok(6),
        "a" => Ok(7),
        "A" => Ok(8),
        _ => Err(json_unknown_variant(v, VARIANTS)),
    }
}
