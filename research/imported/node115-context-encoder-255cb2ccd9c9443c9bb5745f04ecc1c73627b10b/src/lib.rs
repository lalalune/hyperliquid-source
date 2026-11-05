//! Independently authored successful-wire profile of Node115 Ctx.
//! This API is not the captured Rust ABI, allocator or panic contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    Sequence,
    Map,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Timestamp {
    pub packed_date: i32,
    pub seconds: u32,
    pub nanos: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Hardfork {
    pub version: u64,
    pub round: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Context {
    pub hardfork_height: u64,
    pub hardfork: Hardfork,
    pub height: u64,
    pub tx_index: Option<u64>,
    pub round: u64,
    pub time: Timestamp,
    pub prev_time: Timestamp,
    pub next_oid: u64,
    pub next_lid: u64,
    pub next_twap_id: u64,
    pub system_nonce: u64,
    pub use_system_nonce: bool,
    pub mac: u64,
}

/// Safe API validation, not an error variant recovered from the target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutsideTimestampProfile;

/// Format the declared raw-integer timestamp success profile.
///
/// date index < 733, seconds < 86400, nanos < 2000000000.
/// This includes leap-second fractions; it does not infer Chrono constructor
/// invariants. The captured formatter ignores the lowest three date bits.
pub fn timestamp_text(t: Timestamp) -> Result<String, OutsideTimestampProfile> {
    let index = ((t.packed_date as u32) >> 3) & 1023;
    if index >= 733 || t.seconds >= 86400 || t.nanos >= 2_000_000_000 {
        return Err(OutsideTimestampProfile);
    }
    let year = t.packed_date >> 13;
    let ordinal = index / 2;
    let common = index & 1;
    // Regenerate the Gregorian relation; no captured lookup table is copied.
    let (month, day) = if ordinal == 0 {
        (0, 0)
    } else {
        let lengths = [31, 29 - common, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
        let mut remaining = ordinal;
        let mut result = (0, 0);
        for (i, length) in lengths.into_iter().enumerate() {
            if remaining <= length {
                result = (i + 1, remaining);
                break;
            }
            remaining -= length;
        }
        result
    };
    let year_text = if (0..10000).contains(&year) {
        format!("{year:04}")
    } else {
        format!("{year:+05}")
    };
    let hour = t.seconds / 3600;
    let minute = t.seconds / 60 % 60;
    let second = t.seconds % 60 + u32::from(t.nanos >= 1_000_000_000);
    let fraction = t.nanos % 1_000_000_000;
    let suffix = if fraction == 0 {
        String::new()
    } else if fraction.is_multiple_of(1_000_000) {
        format!(".{:03}", fraction / 1_000_000)
    } else if fraction.is_multiple_of(1000) {
        format!(".{:06}", fraction / 1000)
    } else {
        format!(".{fraction:09}")
    };
    Ok(format!(
        "{year_text}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}{suffix}"
    ))
}

fn uint(out: &mut Vec<u8>, value: u64) {
    match value {
        0..=127 => out.push(value as u8),
        128..=255 => out.extend_from_slice(&[0xcc, value as u8]),
        256..=65535 => {
            out.push(0xcd);
            out.extend_from_slice(&(value as u16).to_be_bytes());
        }
        65536..=0xffff_ffff => {
            out.push(0xce);
            out.extend_from_slice(&(value as u32).to_be_bytes());
        }
        _ => {
            out.push(0xcf);
            out.extend_from_slice(&value.to_be_bytes());
        }
    }
}

// All keys and all timestamps in this profile have at most 32 ASCII bytes.
// This helper is deliberately private, not a general MessagePack string API.
fn string(out: &mut Vec<u8>, value: &str) {
    let n = value.len();
    if n < 32 {
        out.push(0xa0 | n as u8);
    } else {
        out.extend_from_slice(&[0xd9, n as u8]);
    }
    out.extend_from_slice(value.as_bytes());
}

fn key(out: &mut Vec<u8>, mode: Mode, value: &str) {
    if mode == Mode::Map {
        string(out, value);
    }
}

/// Encode all thirteen fields, with nested hardfork following the same mode.
///
/// Success bytes are derived from the authenticated Node115 operands.
/// Allocation failure, partial append state, native Result layout and invalid
/// source-language values are outside this safe API's equivalence claim.
pub fn encode(ctx: &Context, mode: Mode) -> Result<Vec<u8>, OutsideTimestampProfile> {
    let mut out = vec![if mode == Mode::Map { 0x8d } else { 0x9d }];
    key(&mut out, mode, "hardfork_height");
    uint(&mut out, ctx.hardfork_height);
    key(&mut out, mode, "hardfork");
    out.push(if mode == Mode::Map { 0x82 } else { 0x92 });
    key(&mut out, mode, "version");
    uint(&mut out, ctx.hardfork.version);
    key(&mut out, mode, "round");
    uint(&mut out, ctx.hardfork.round);
    key(&mut out, mode, "height");
    uint(&mut out, ctx.height);
    key(&mut out, mode, "tx_index");
    match ctx.tx_index {
        Some(value) => uint(&mut out, value),
        None => out.push(0xc0),
    }
    key(&mut out, mode, "round");
    uint(&mut out, ctx.round);
    key(&mut out, mode, "time");
    string(&mut out, &timestamp_text(ctx.time)?);
    key(&mut out, mode, "prev_time");
    string(&mut out, &timestamp_text(ctx.prev_time)?);
    for (name, value) in [
        ("next_oid", ctx.next_oid),
        ("next_lid", ctx.next_lid),
        ("next_twap_id", ctx.next_twap_id),
        ("system_nonce", ctx.system_nonce),
    ] {
        key(&mut out, mode, name);
        uint(&mut out, value);
    }
    key(&mut out, mode, "use_system_nonce");
    out.push(if ctx.use_system_nonce { 0xc3 } else { 0xc2 });
    key(&mut out, mode, "mac");
    uint(&mut out, ctx.mac);
    Ok(out)
}
