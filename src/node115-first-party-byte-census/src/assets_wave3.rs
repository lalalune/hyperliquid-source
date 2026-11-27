//! Wave 3 first-party `assets` compiled-byte business-logic functions (`l1/src/spot_meta.rs`, `l1/src/perp_meta.rs`).

static POW10_256: [f64; 256] = {
    let mut a = [1.0; 256];
    let mut i = 1;
    while i < 256 {
        a[i] = a[i - 1] * 10.0;
        i += 1;
    }
    a
};

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenSpec {
    pub _pad: [u8; 0x18],
    pub sz_decimals: u8,
    pub wei_decimals: u8,
}

#[inline(never)]
pub fn assets_token_wei_per_sz(spec: &TokenSpec) -> u64 {
    fn inner(spec: &TokenSpec) -> Option<u64> {
        let diff = spec.wei_decimals.checked_sub(spec.sz_decimals)?;
        10_u64.checked_pow(u32::from(diff))
    }
    inner(spec).unwrap()
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpotInfo {
    pub tokens: [usize; 2],
    pub _pad: [u8; 0x10],
}

#[repr(C)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenInfo {
    pub _pad0: [u8; 0x38],
    pub name_ptr: usize,
    pub name_len: usize,
    pub sz_decimals: u8,
    pub wei_decimals: u8,
    pub _pad1: [u8; 6],
    pub spots: Vec<usize>,
    pub _pad2: [u8; 0x158 - 0x68],
}

#[repr(C)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpotMeta {
    pub universe: Vec<SpotInfo>,
    pub token_infos: Vec<TokenInfo>,
}

#[inline(always)]
fn spot_token_info(meta: &SpotMeta, token: usize) -> &TokenInfo {
    meta.token_infos.get(token).unwrap()
}

#[inline(never)]
pub fn assets_first_spot_for_token(meta: &SpotMeta, token: usize) -> Option<usize> {
    spot_token_info(meta, token).spots.first().copied()
}

#[allow(clippy::manual_find)]
#[inline(never)]
pub fn assets_spot_for_quote(
    meta: &SpotMeta,
    base_token: usize,
    quote_token: usize,
) -> Option<usize> {
    for &spot in &spot_token_info(meta, base_token).spots {
        if meta.universe[spot].tokens[1] == quote_token {
            return Some(spot);
        }
    }
    None
}

#[inline(never)]
pub fn assets_quote_name_pair(meta: &SpotMeta, spot: usize) -> (usize, usize) {
    let quote = meta.universe[spot].tokens[1];
    let info = spot_token_info(meta, quote);
    (info.name_ptr, info.name_len)
}

#[inline(never)]
pub fn assets_checked_sz_to_wei(meta: &SpotMeta, token: usize, sz: u64) -> Option<u64> {
    fn inner(info: &TokenInfo) -> Option<u64> {
        let diff = info.wei_decimals.checked_sub(info.sz_decimals)?;
        10_u64.checked_pow(u32::from(diff))
    }
    let scale = inner(spot_token_info(meta, token)).unwrap();
    sz.checked_mul(scale)
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PerpAssetInfo {
    pub _pad0: [u8; 0x1d],
    pub sz_decimals: u8,
    pub _pad1: [u8; 2],
}

#[repr(C)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PerpMeta {
    pub universe: Vec<PerpAssetInfo>,
    pub _pad1: [u8; 0x50 - 24],
    pub pdi: usize,
}

#[inline(never)]
pub fn assets_perp_px_decimals(meta: &PerpMeta, asset: usize) -> u8 {
    let pdi = asset / 10_000;
    let local = asset % 10_000;
    let info = if pdi == meta.pdi {
        meta.universe.get(local)
    } else {
        None
    }
    .unwrap();
    6_u8 - info.sz_decimals
}

#[inline(never)]
pub fn assets_perp_sz_to_f64(raw: u64, asset: usize, meta: &PerpMeta) -> f64 {
    if raw == 0 {
        return 0.0;
    }
    let pdi = asset / 10_000;
    let local = asset % 10_000;
    let info = if pdi == meta.pdi {
        meta.universe.get(local)
    } else {
        None
    }
    .unwrap();
    (raw as f64) / POW10_256[usize::from(info.sz_decimals)]
}

#[inline(never)]
pub fn assets_perp_px_to_f64(raw: u64, asset: usize, meta: &PerpMeta) -> f64 {
    let pdi = asset / 10_000;
    let local = asset % 10_000;
    let info = if pdi == meta.pdi {
        meta.universe.get(local)
    } else {
        None
    }
    .unwrap();
    let px_dec = 6_u8 - info.sz_decimals;
    (raw as f64) / POW10_256[usize::from(px_dec)]
}
