#![no_std]
//! Conditional single-probe semantics from node #115, not a compressor or ABI.

/// A safe adapter rejects inputs outside the native loop's established domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BeforeProbe {
    /// The native outer loop requires position <= source length - 12.
    InvalidPosition,
    /// Native checked origin + position takes an opaque failure-helper edge.
    AbsoluteOverflow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Native current - previous subtraction borrows: opaque failure boundary.
    CandidateAhead,
    BeforeOrigin,
    TooFar,
    Different,
    Match {
        candidate: usize,
        distance: u64,
    },
}

/// The bucket has already been written even for a non-match or failure boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Probe {
    pub bucket: usize,
    pub previous: u64,
    pub stored: u64,
    pub verdict: Verdict,
}

pub fn small_bucket(word: [u8; 4]) -> usize {
    (u32::from_le_bytes(word).wrapping_mul(0x9e37_79b1) >> 20) as usize
}

pub fn large_bucket(word: [u8; 8]) -> usize {
    (u64::from_le_bytes(word).wrapping_mul(0xcf1b_bcdc_bb00_0000) >> 52) as usize
}

fn current(source: &[u8], position: usize, origin: u64) -> Result<u64, BeforeProbe> {
    if source.len() < 12 || position > source.len() - 12 {
        return Err(BeforeProbe::InvalidPosition);
    }
    origin
        .checked_add(position as u64)
        .ok_or(BeforeProbe::AbsoluteOverflow)
}

fn judge(source: &[u8], position: usize, origin: u64, absolute: u64, old: u64) -> Verdict {
    let Some(distance) = absolute.checked_sub(old) else {
        return Verdict::CandidateAhead;
    };
    let Some(relative) = old.checked_sub(origin) else {
        return Verdict::BeforeOrigin;
    };
    if distance >= 65_536 {
        return Verdict::TooFar;
    }
    // Under the checked current-position domain, relative <= position. Thus
    // relative+4 <= source.len()-8: the native candidate-bounds failure edge
    // cannot be reached by this safe adapter. No invented failure ABI is used.
    let candidate = relative as usize;
    if source[candidate..candidate + 4] != source[position..position + 4] {
        return Verdict::Different;
    }
    Verdict::Match {
        candidate,
        distance,
    }
}

/// Source domain is the native outer loop's position <= len-12. The supplied
/// table is caller-owned; this function does not initialize any bucket.
pub fn small_probe(
    table: &mut [u16; 4096],
    source: &[u8],
    position: usize,
    origin: u64,
) -> Result<Probe, BeforeProbe> {
    let absolute = current(source, position, origin)?;
    let bucket = small_bucket(source[position..position + 4].try_into().unwrap());
    let previous = u64::from(table[bucket]);
    let stored = absolute as u16;
    table[bucket] = stored;
    Ok(Probe {
        bucket,
        previous,
        stored: u64::from(stored),
        verdict: judge(source, position, origin, absolute, previous),
    })
}

/// The large hash loads eight bytes; the candidate comparison still uses four.
pub fn large_probe(
    table: &mut [u32; 4096],
    source: &[u8],
    position: usize,
    origin: u64,
) -> Result<Probe, BeforeProbe> {
    let absolute = current(source, position, origin)?;
    let bucket = large_bucket(source[position..position + 8].try_into().unwrap());
    let previous = u64::from(table[bucket]);
    let stored = absolute as u32;
    table[bucket] = stored;
    Ok(Probe {
        bucket,
        previous,
        stored: u64::from(stored),
        verdict: judge(source, position, origin, absolute, previous),
    })
}
