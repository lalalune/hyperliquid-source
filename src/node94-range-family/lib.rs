#![no_std]
#![forbid(unsafe_code)]
pub const LO: u64 = 0x599a730;
pub const HI: u64 = 0x599a720;

/// Full RAX, including bits 8..31 retained from incoming registers.
#[inline(never)]
pub fn range_value<E>(
    value: u64,
    old_rax: u64,
    old_rcx: u64,
    mut load: impl FnMut(u64) -> Result<u64, E>,
) -> Result<u64, E> {
    let hi = load(HI)?;
    let lo = load(LO)?;
    Ok((old_rax & old_rcx & 0xffff_ff00) | u64::from(lo <= value && value < hi))
}

/// Adjacent FDE [0x5520e20, 0x5520e71). LO is intentionally reloaded.
/// Values returned by load describe observed reads; no concurrency claim.
#[inline(never)]
pub fn same_membership<E>(
    left: u64,
    right: u64,
    mut load: impl FnMut(u64) -> Result<u64, E>,
) -> Result<u64, E> {
    let initial_lo = load(LO)?;
    if left < initial_lo && right < initial_lo {
        return Ok(1);
    }
    let hi = load(HI)?;
    let lo = load(LO)?;
    let left_inside = lo <= left && left < hi;
    let right_inside = lo <= right && right < hi;
    Ok((lo & 0xffff_ff00) | u64::from(left_inside == right_inside))
}

#[cfg(test)]
extern crate self as node94_leaf;
#[cfg(test)]
extern crate std;
#[cfg(test)]
mod client_support;
#[cfg(test)]
mod tests {
    use super::client_support;
    use std::vec::Vec;
    #[test]
    fn frozen_pre_rust_observations() {
        let mut cases = 0;
        for row in include_str!("vectors.tsv").lines() {
            let columns: Vec<_> = row.split('\t').collect();
            let input: Vec<u64> = columns[1].split(',').map(|s| s.parse().unwrap()).collect();
            let expected: Vec<u64> = columns[2].split(',').map(|s| s.parse().unwrap()).collect();
            assert_eq!(
                client_support::evaluate(&input),
                expected,
                "case {}",
                columns[0]
            );
            cases += 1;
        }
        assert_eq!(cases, 4240);
    }
}
