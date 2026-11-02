use std::collections::BTreeMap;
use std::{vec, vec::Vec};
pub fn evaluate(w: &[u64]) -> Vec<u64> {
    let mut memory = BTreeMap::new();
    let mut put = |a: u64, v: u64| {
        for (i, b) in v.to_le_bytes().into_iter().enumerate() {
            memory.insert(a.wrapping_add(i as u64), b);
        }
    };
    if w[0] == 0 {
        put(w[1].wrapping_add(8), w[2]);
        put(w[2].wrapping_add(0x928), w[3]);
        if w[5] == 0 {
            put(w[2].wrapping_add(0x948), w[4]);
        }
    } else {
        put(w[1].wrapping_add(0x1458), w[3]);
        if w[5] == 0 {
            put(w[1].wrapping_add(0x1478), w[4]);
        }
    }
    let mut reads = Vec::new();
    let mut load = |a: u64| {
        reads.push(a);
        let mut bytes = [0; 8];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = *memory.get(&a.wrapping_add(i as u64)).ok_or(())?;
        }
        Ok::<u64, ()>(u64::from_le_bytes(bytes))
    };
    let result = if w[0] == 0 {
        node94_leaf::dual_zero(w[1], &mut load)
    } else {
        node94_leaf::field_inequality(w[1], &mut load).map(|rax| (rax, 0))
    };
    let mut output = match result {
        Ok((rax, aux)) => vec![0, rax, aux, reads.len() as u64],
        Err(()) => vec![1, 0, 0, reads.len() as u64],
    };
    output.extend(reads);
    output
}
