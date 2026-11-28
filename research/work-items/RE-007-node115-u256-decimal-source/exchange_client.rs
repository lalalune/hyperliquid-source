//! Read the existing arbitrary-precision corpus through the public exchange API.
use exchange::token_scaling::{signed_exponent_scale_u256, U256};
use std::io::{self, BufRead};

fn limbs(hex: &str) -> [u64; 4] {
    std::array::from_fn(|i| {
        let end = 64 - i * 16;
        u64::from_str_radix(&hex[end - 16..end], 16).expect("four little-endian limbs")
    })
}

fn main() {
    let mut rows = 0;
    let mut wrong_return = 0;
    let mut wrong_state_on_success = 0;
    let mut wrong_state_on_refusal = 0;
    for line in io::stdin().lock().lines() {
        let line = line.expect("read corpus");
        let mut fields = line.split_whitespace();
        let exponent = fields.next().unwrap().parse().unwrap();
        let mut input = U256(limbs(fields.next().unwrap()));
        let expected_input = limbs(fields.next().unwrap());
        let expected = fields.next().unwrap().parse::<i64>().unwrap();
        assert!(fields.next().is_none());
        let expected = u64::try_from(expected).ok();
        let observed = signed_exponent_scale_u256(exponent, &mut input);
        wrong_return += usize::from(observed != expected);
        if input.0 != expected_input {
            if expected.is_some() {
                wrong_state_on_success += 1;
            } else {
                wrong_state_on_refusal += 1;
            }
        }
        rows += 1;
    }
    let mut amount = U256([50, 0, 0, 0]);
    let multiplied = signed_exponent_scale_u256(-2, &mut amount).unwrap();
    let after_multiply = amount.0;
    let divided = signed_exponent_scale_u256(1, &mut amount).unwrap();
    println!("{{");
    println!("  \"rows\": {rows}, \"wrong_return\": {wrong_return},");
    println!("  \"wrong_state_on_success\": {wrong_state_on_success},");
    println!("  \"wrong_state_on_refusal\": {wrong_state_on_refusal},");
    println!("  \"multiply_return\": {multiplied}, \"after_multiply\": {after_multiply:?},");
    println!(
        "  \"next_divide_return\": {divided}, \"after_divide\": {:?}",
        amount.0
    );
    println!("}}");
}
