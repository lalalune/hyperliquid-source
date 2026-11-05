//! Logical JSON success contract of the Node115 asset-metadata writer.
//! This is an independently authored API, not the original Rust layout or errors.
pub use node115_context_encoder::{OutsideTimestampProfile, Timestamp};
use std::fmt::Write;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MarginMode {
    Normal,
    NoCross,
    StrictIsolated,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GrowthMode {
    Enabled,
    Disabled,
    Blocked,
}

/// Named logical values. Captured offsets and raw enum layout are evidence only.
#[derive(Clone, Copy, Debug)]
pub struct AssetMetadata<'a> {
    pub sz_decimals: u8,
    pub name: &'a str,
    pub max_leverage: u8,
    pub margin_table_id: u32,
    pub only_isolated: bool,
    pub is_delisted: bool,
    pub margin_mode: MarginMode,
    pub growth_mode: GrowthMode,
    pub last_fee_scale_change_time: Option<Timestamp>,
    pub deployer_fee_scale: Option<f64>,
}

fn quoted(out: &mut String, value: &str) {
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            c if (c as u32) < 32 => write!(out, "\\u{:04x}", c as u32).unwrap(),
            c => out.push(c),
        }
    }
    out.push('"');
}

fn string_field(out: &mut String, key: &str, value: &str) {
    out.push(',');
    quoted(out, key);
    out.push(':');
    quoted(out, value);
}

fn fee_text(value: f64) -> String {
    let mut text = format!("{value:.10}");
    // The original keeps one zero after the decimal point.
    while text.ends_with('0') && !text.ends_with(".0") {
        text.pop();
    }
    if text == "-0.0" {
        text.replace_range(.., "0.0");
    }
    text
}

/// Encode all ten logical fields in the observed order and with their defaults.
///
/// The selected success domain uses valid UTF-8 strings, canonical three-way
/// modes and the retained timestamp's raw-integer profile. A present timestamp
/// cannot have packed_date=0: the captured niche would represent absence.
/// Every binary64 bit pattern is accepted for the quoted fee-scale value.
///
/// The local validation error is not the captured error pointer/Result.
/// Allocation failure, partial append, panic/unwind and native ABI are unclaimed.
pub fn encode(value: &AssetMetadata<'_>) -> Result<String, OutsideTimestampProfile> {
    let time = match value.last_fee_scale_change_time {
        None => None,
        Some(t) => {
            if t.packed_date == 0 {
                return Err(OutsideTimestampProfile);
            }
            Some(node115_context_encoder::timestamp_text(t)?)
        }
    };
    let mut out = String::new();
    write!(out, "{{\"szDecimals\":{},\"name\":", value.sz_decimals).unwrap();
    quoted(&mut out, value.name);
    write!(
        out,
        ",\"maxLeverage\":{},\"marginTableId\":{}",
        value.max_leverage, value.margin_table_id
    )
    .unwrap();
    if value.only_isolated {
        out.push_str(",\"onlyIsolated\":true");
    }
    if value.is_delisted {
        out.push_str(",\"isDelisted\":true");
    }
    match value.margin_mode {
        MarginMode::Normal => {}
        MarginMode::NoCross => string_field(&mut out, "marginMode", "noCross"),
        MarginMode::StrictIsolated => string_field(&mut out, "marginMode", "strictIsolated"),
    }
    match value.growth_mode {
        GrowthMode::Enabled => string_field(&mut out, "growthMode", "enabled"),
        GrowthMode::Disabled => {}
        GrowthMode::Blocked => string_field(&mut out, "growthMode", "blocked"),
    }
    if let Some(time) = time {
        string_field(&mut out, "lastFeeScaleChangeTime", &time);
    }
    if let Some(fee) = value.deployer_fee_scale {
        string_field(&mut out, "deployerFeeScale", &fee_text(fee));
    }
    out.push('}');
    Ok(out)
}
