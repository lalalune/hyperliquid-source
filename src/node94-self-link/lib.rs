#![no_std]
#![forbid(unsafe_code)]
/// Byte-view store primitives, not the captured function's native pointer ABI.
pub trait Store {
    type Error;
    fn store_u64(&mut self, address: u64, value: u64) -> Result<(), Self::Error>;
    fn store_u8(&mut self, address: u64, value: u8) -> Result<(), Self::Error>;
}

#[derive(Debug, PartialEq, Eq)]
pub struct Registers {
    pub rax: u64,
    pub rdx: u64,
}

/// Node94 [0x4f91ee0,0x4f91efb): three ordered stores, no input loads.
/// A primitive refusal is propagated; preceding successful stores are retained.
#[inline(never)]
pub fn self_link_initialize<M: Store>(memory: &mut M, base: u64) -> Result<Registers, M::Error> {
    let rdx = base.wrapping_add(16);
    memory.store_u64(base.wrapping_add(8), 0)?;
    memory.store_u64(base, rdx)?;
    memory.store_u8(base.wrapping_add(16), 0)?;
    Ok(Registers { rax: base, rdx })
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
        assert_eq!(cases, 6346);
    }
}
