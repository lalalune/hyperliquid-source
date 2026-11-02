#![no_std]
#![forbid(unsafe_code)]
/// Safe value/read-order model, not a native-pointer ABI or fault emulator.
/// Returns full RAX, RDX, and RSI on successful reads.
#[inline(never)]
pub fn byte_index<E>(
    base: u64,
    incoming_rsi: u64,
    mut load: impl FnMut(u64) -> Result<u8, E>,
) -> Result<(u64, u64, u64), E> {
    let count = load(base.wrapping_add(1))? as u64;
    let index = incoming_rsi as u32 as u64;
    if index > count {
        return Ok((0, count, incoming_rsi));
    }
    let value = load(base.wrapping_add(index.wrapping_mul(8)).wrapping_add(8))?;
    Ok((value as u64, count, index))
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
        assert_eq!(cases, 68193);
    }
}
