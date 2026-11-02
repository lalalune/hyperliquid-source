use std::{vec, vec::Vec};
pub fn evaluate(w: &[u64]) -> Vec<u64> {
    let (rax, rdx) = node94_leaf::negative_band(w[0]);
    vec![rax, rdx]
}
