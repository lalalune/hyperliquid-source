extern crate node94_leaf;
use std::io::{self, BufRead};
fn evaluate(x: Vec<u64>) -> Vec<u64> {
    let r = node94_leaf::continue_after_call(node94_leaf::PostCall {
        rax: x[0],
        rdx: x[1],
        rsi: x[2],
    });
    vec![r.rax, r.rcx, r.rdx, r.rsi]
}
fn main() {
    for line in io::stdin().lock().lines() {
        let x = line
            .unwrap()
            .split(',')
            .map(|s| s.parse().unwrap())
            .collect();
        println!(
            "{}",
            evaluate(x)
                .iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join(",")
        );
    }
}
