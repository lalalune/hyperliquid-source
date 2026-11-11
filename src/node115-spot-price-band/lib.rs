//! Logical spot admission and price-band projection for selected node115 paths.
#![no_std]
#![forbid(unsafe_code)]

/// Unique-key logical projections of the native metadata containers.
pub struct SpotMetadata<'a> {
    pub tokens: &'a [u64],
    pub excluded: &'a [u64],
    pub routes: &'a [(u64, u64)],
    pub available: &'a [u64],
}

/// Only observed status and active payload are projected; this is not native ABI.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Decision {
    pub status: u16,
    pub band_percent: Option<f64>,
}

/// An owned representation of the native out-of-range token-index panic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidIndex;

const fn status(status: u16) -> Decision {
    Decision {
        status,
        band_percent: None,
    }
}

/// Apply the selected common numerical price-band condition in native order.
/// All operations require the usual binary64 round-to-nearest environment.
pub fn band(a: u64, b: u64, p: f64) -> Decision {
    let ratio = a as f64 / b as f64 - 1.0;
    if p > ratio.abs() || (1.0 > p && ratio > 0.0 && 1.0 / (1.0 - p) - 1.0 >= ratio) {
        status(0x1a2)
    } else {
        Decision {
            status: 0x63,
            band_percent: Some(p * 100.0),
        }
    }
}

/// The eight 20-byte inputs accepted by the selected native exemption helper.
pub const EXEMPT_KEYS: [[u8; 20]; 8] = [
    [
        0x01, 0x04, 0x61, 0xc1, 0x4e, 0x14, 0x6a, 0xc3, 0x5f, 0xe4, 0x22, 0x71, 0xbd, 0xc1, 0x13,
        0x4e, 0xe3, 0x1c, 0x70, 0x3a,
    ],
    [
        0x31, 0xca, 0x83, 0x95, 0xcf, 0x83, 0x7d, 0xe0, 0x8b, 0x24, 0xda, 0x3f, 0x66, 0x0e, 0x77,
        0x76, 0x1d, 0xfb, 0x97, 0x4b,
    ],
    [
        0x76, 0x84, 0x84, 0xf7, 0xe2, 0xeb, 0xb6, 0x75, 0xc5, 0x78, 0x38, 0x36, 0x6c, 0x02, 0xae,
        0x99, 0xba, 0x2a, 0x9b, 0x08,
    ],
    [
        0xc6, 0x4c, 0xc0, 0x0b, 0x46, 0x10, 0x1b, 0xd4, 0x0a, 0xa1, 0xc3, 0x12, 0x11, 0x95, 0xe8,
        0x5c, 0x0b, 0x09, 0x18, 0xd8,
    ],
    [
        0x07, 0xbe, 0xd5, 0xc0, 0x83, 0x06, 0xe0, 0x26, 0x79, 0x7e, 0x5e, 0xa9, 0x3c, 0x29, 0x3a,
        0xbc, 0x56, 0x73, 0xc2, 0xad,
    ],
    [
        0x93, 0xe2, 0x55, 0x1d, 0x82, 0x1d, 0xda, 0x10, 0x80, 0xa3, 0x72, 0xf0, 0xb0, 0x4b, 0x86,
        0x46, 0x83, 0x20, 0x33, 0x3d,
    ],
    [
        0xa1, 0x50, 0x99, 0xa3, 0x0b, 0xbf, 0x2e, 0x68, 0x94, 0x2d, 0x6f, 0x4c, 0x43, 0xd7, 0x0d,
        0x04, 0xfa, 0xea, 0xb0, 0xa0,
    ],
    [
        0xdf, 0xc2, 0x4b, 0x07, 0x7b, 0xc1, 0x42, 0x5a, 0xd1, 0xde, 0xa7, 0x5b, 0xcb, 0x6f, 0x81,
        0x58, 0xe1, 0x0d, 0xf3, 0x03,
    ],
];

/// Apply the selected perp gate, including the actual fixed-key bypass.
pub fn perp(key: &[u8; 20], a: u64, b: u64, p: f64) -> Decision {
    if EXEMPT_KEYS.contains(key) {
        status(0x1a2)
    } else {
        band(a, b, p)
    }
}

/// Apply the selected spot gate to valid, stable logical metadata containers.
/// Route keys must be unique; no physical tree or hash-map layout is claimed.
pub fn spot(
    meta: &SpotMetadata<'_>,
    index: usize,
    a: u64,
    b: u64,
    p: f64,
) -> Result<Decision, InvalidIndex> {
    let key = *meta.tokens.get(index).ok_or(InvalidIndex)?;
    if meta.excluded.contains(&key) {
        return Ok(status(0x195));
    }
    let Some((_, target)) = meta.routes.iter().find(|(k, _)| *k == key) else {
        return Ok(band(a, b, p));
    };
    if !meta.available.contains(target) {
        return Ok(status(0x195));
    }
    Ok(status(if a <= 99_999_000 { 0x1a2 } else { 0x100 }))
}
