#![no_std]
#![forbid(unsafe_code)]
/// Read/write primitives over an ordinary byte view, not native ABI or faults.
pub trait Memory {
    type Error;
    fn load_u64(&mut self, address: u64) -> Result<u64, Self::Error>;
    fn store_u64(&mut self, address: u64, value: u64) -> Result<(), Self::Error>;
}

#[derive(Debug, PartialEq, Eq)]
pub struct Registers {
    pub rax: u64,
    pub rdx: u64,
    pub rsi: u64,
}

/// Node94 [0x514abb0,0x514abe3). The object arrives in RDX, output in RSI.
/// Required reads precede the sole write; aliases are not assumed disjoint.
#[inline(never)]
pub fn sentinel_field_read<M: Memory>(
    memory: &mut M,
    object: u64,
    output: u64,
) -> Result<Registers, M::Error> {
    let entry = memory.load_u64(object.wrapping_add(0x1200))?;
    let sentinel = object.wrapping_add(0x11e0);
    let stored = if entry == sentinel {
        0
    } else {
        memory.load_u64(entry.wrapping_add(0x30))?
    };
    memory.store_u64(output, stored)?;
    Ok(Registers {
        rax: 1,
        rdx: sentinel,
        rsi: output,
    })
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
        assert_eq!(cases, 2788);
    }
}
