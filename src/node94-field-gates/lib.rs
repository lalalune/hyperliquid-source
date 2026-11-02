#![no_std]
#![forbid(unsafe_code)]
/// Full RAX and loaded RDX, with the target's short-circuit load order.
#[inline(never)]
pub fn dual_zero<E>(
    base: u64,
    mut load: impl FnMut(u64) -> Result<u64, E>,
) -> Result<(u64, u64), E> {
    let pointer = load(base.wrapping_add(8))?;
    let first = load(pointer.wrapping_add(0x928))?;
    if first != 0 {
        return Ok((0, pointer));
    }
    let second = load(pointer.wrapping_add(0x948))?;
    Ok((u64::from(second == 0), pointer))
}

/// Full RAX retains bits 8..63 of the first field, rather than a Boolean.
#[inline(never)]
pub fn field_inequality<E>(
    base: u64,
    mut load: impl FnMut(u64) -> Result<u64, E>,
) -> Result<u64, E> {
    let first = load(base.wrapping_add(0x1458))?;
    let second = load(base.wrapping_add(0x1478))?;
    Ok((first & !255) | u64::from(first != second))
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
        assert_eq!(cases, 2385);
    }
}
