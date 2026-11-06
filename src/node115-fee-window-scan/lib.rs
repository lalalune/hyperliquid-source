#![no_std]
#![forbid(unsafe_code)]
//! Qualified normal-return relation; no original ABI or fee-validation claim.
#[derive(Debug, PartialEq, Eq)]
pub struct Scan {
    pub found: bool,
    pub consumed: usize,
    pub remaining: u64,
}
fn finish(found: bool, consumed: usize, remaining: u64) -> Scan {
    Scan {
        found,
        consumed,
        remaining,
    }
}
fn signaling_nan(bits: u64) -> bool {
    bits & 0x7ff0_0000_0000_0000 == 0x7ff0_0000_0000_0000
        && bits & 0x000f_ffff_ffff_ffff != 0
        && bits & 0x0008_0000_0000_0000 == 0
}
/// An owned refusal (`None`) excludes signaling NaNs and the nonempty
/// invalid-width diagnostic. Ordinary IEEE comparisons, DAZ clear and masked
/// denormal exceptions are premises; caller admission/environment is unknown.
pub fn scan(bits: &[u64], width: u64) -> Option<Scan> {
    if (width < 2 && !bits.is_empty()) || bits.iter().copied().any(signaling_nan) {
        return None;
    }
    let mut remaining = bits.len() as u64;
    let mut consumed = 0;
    if width < 2 {
        return Some(finish(false, consumed, remaining));
    }
    while remaining >= width {
        remaining -= 1;
        consumed += 1;
        let current = f64::from_bits(bits[consumed]);
        let previous = f64::from_bits(bits[consumed - 1]);
        if current > previous {
            return Some(finish(true, consumed, remaining));
        }
    }
    Some(finish(false, consumed, remaining))
}
