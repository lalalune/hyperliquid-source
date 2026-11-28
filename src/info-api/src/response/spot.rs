//! Serialize selected spot account values after lookup and numeric formatting.
use std::collections::BTreeMap;
use std::io::{self, Write};

/// Display numbers are the decimal strings already produced by the caller.
#[derive(Default)]
pub struct Balance<'a> {
    pub coin: &'a str,
    pub token: Option<u64>,
    pub total: &'a str,
    pub hold: &'a str,
    pub entry_ntl: &'a str,
    pub spot_hold: Option<&'a str>,
    pub ltv: Option<&'a str>,
    pub borrowed: Option<&'a str>,
    pub supplied: Option<&'a str>,
}

pub struct EvmEscrow<'a> {
    pub coin: &'a str,
    pub token: u64,
    pub total: &'a str,
}

pub type TokenValues<'a> = BTreeMap<u64, &'a str>;

#[derive(Default)]
pub struct SpotState<'a> {
    pub portfolio_margin_enabled: bool,
    pub balances: &'a [Balance<'a>],
    pub evm_escrows: &'a [EvmEscrow<'a>],
    pub portfolio_margin_ratio: Option<&'a str>,
    pub token_to_portfolio_borrow_ratio: Option<&'a TokenValues<'a>>,
    pub token_to_portfolio_supply_ratio: Option<&'a TokenValues<'a>>,
    pub token_to_available_after_maintenance: Option<&'a TokenValues<'a>>,
}

// Emit UTF-8 runs verbatim and escape JSON string delimiters and controls.
fn string(out: &mut impl Write, value: &str) -> io::Result<()> {
    out.write_all(b"\"")?;
    let bytes = value.as_bytes();
    let mut start = 0;
    for (i, &byte) in bytes.iter().enumerate() {
        let escaped: &[u8] = match byte {
            b'"' => br#"\""#,
            b'\\' => br"\\",
            8 => br"\b",
            9 => br"\t",
            10 => br"\n",
            12 => br"\f",
            13 => br"\r",
            0..=31 => b"",
            _ => continue,
        };
        out.write_all(&bytes[start..i])?;
        if escaped.is_empty() {
            write!(out, "\\u{byte:04x}")?;
        } else {
            out.write_all(escaped)?;
        }
        start = i + 1;
    }
    out.write_all(&bytes[start..])?;
    out.write_all(b"\"")
}

fn array<W: Write, T>(
    out: &mut W,
    items: impl IntoIterator<Item = T>,
    mut item: impl FnMut(&mut W, T) -> io::Result<()>,
) -> io::Result<()> {
    out.write_all(b"[")?;
    for (i, value) in items.into_iter().enumerate() {
        if i != 0 {
            out.write_all(b",")?;
        }
        item(out, value)?;
    }
    out.write_all(b"]")
}

fn balance(out: &mut impl Write, row: &Balance<'_>) -> io::Result<()> {
    out.write_all(br#"{"coin":"#)?;
    string(out, row.coin)?;
    if let Some(token) = row.token {
        write!(out, ",\"token\":{token}")?;
    }
    for (name, value) in [
        ("total", Some(row.total)),
        ("hold", Some(row.hold)),
        ("entryNtl", Some(row.entry_ntl)),
        ("spotHold", row.spot_hold),
        ("ltv", row.ltv),
        ("borrowed", row.borrowed),
        ("supplied", row.supplied),
    ] {
        if let Some(value) = value {
            write!(out, ",\"{name}\":")?;
            string(out, value)?;
        }
    }
    out.write_all(b"}")
}

/// Emit the node #115 JSON shape. Balance and escrow rows retain input order.
/// A present empty token map is emitted as an empty array. A missing map is omitted.
pub fn write_spot_state(out: &mut impl Write, state: &SpotState<'_>) -> io::Result<()> {
    out.write_all(b"{")?;
    if state.portfolio_margin_enabled {
        out.write_all(br#""portfolioMarginEnabled":true,"#)?;
    }
    out.write_all(br#""balances":"#)?;
    array(out, state.balances, balance)?;
    if !state.evm_escrows.is_empty() {
        out.write_all(br#","evmEscrows":"#)?;
        array(out, state.evm_escrows, |out, escrow| {
            out.write_all(br#"{"coin":"#)?;
            string(out, escrow.coin)?;
            write!(out, ",\"token\":{},\"total\":", escrow.token)?;
            string(out, escrow.total)?;
            out.write_all(b"}")
        })?;
    }
    if let Some(value) = state.portfolio_margin_ratio {
        out.write_all(br#","portfolioMarginRatio":"#)?;
        string(out, value)?;
    }
    for (name, values) in [
        (
            "tokenToPortfolioBorrowRatio",
            state.token_to_portfolio_borrow_ratio,
        ),
        (
            "tokenToPortfolioSupplyRatio",
            state.token_to_portfolio_supply_ratio,
        ),
        (
            "tokenToAvailableAfterMaintenance",
            state.token_to_available_after_maintenance,
        ),
    ] {
        if let Some(values) = values {
            write!(out, ",\"{name}\":")?;
            array(out, values, |out, (token, value)| {
                write!(out, "[{token},")?;
                string(out, value)?;
                out.write_all(b"]")
            })?;
        }
    }
    out.write_all(b"}")
}
