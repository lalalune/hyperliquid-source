use std::collections::BTreeMap;
use std::{vec, vec::Vec};
pub fn evaluate(w: &[u64]) -> Vec<u64> {
    let mut memory = BTreeMap::new();
    memory.insert(w[0].wrapping_add(1), w[2] as u8);
    if w[4] != 0 {
        memory.insert(
            w[0].wrapping_add((w[1] as u32 as u64).wrapping_mul(8))
                .wrapping_add(8),
            w[3] as u8,
        );
    }
    let mut reads = Vec::new();
    let result = node94_leaf::byte_index(w[0], w[1], |a| {
        reads.push(a);
        memory.get(&a).copied().ok_or(())
    });
    let mut output = match result {
        Ok((rax, rdx, rsi)) => vec![0, rax, rdx, rsi, reads.len() as u64],
        Err(()) => vec![1, 0, 0, 0, reads.len() as u64],
    };
    output.extend(reads);
    output
}
