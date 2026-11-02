use std::{vec, vec::Vec};
pub fn evaluate(w: &[u64]) -> Vec<u64> {
    vec![node94_leaf::pointer_sum(w[0], w[1])]
}
