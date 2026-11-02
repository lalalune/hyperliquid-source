use std::{vec, vec::Vec};
pub fn evaluate(w: &[u64]) -> Vec<u64> {
    let mut reads = Vec::new();
    let result = if w[0] == 0 {
        node94_leaf::range_value(w[1], w[4], w[5], |a| {
            reads.push(a);
            Ok::<u64, ()>(if a == node94_leaf::HI { w[3] } else { w[2] })
        })
    } else {
        let mut lower_reads = 0;
        node94_leaf::same_membership(w[1], w[2], |a| {
            reads.push(a);
            if a == node94_leaf::HI {
                Ok::<u64, ()>(w[4])
            } else {
                lower_reads += 1;
                Ok(if lower_reads == 1 { w[3] } else { w[5] })
            }
        })
    };
    let mut output = vec![
        result.expect("complete synthetic read values"),
        reads.len() as u64,
    ];
    output.extend(reads);
    output
}
