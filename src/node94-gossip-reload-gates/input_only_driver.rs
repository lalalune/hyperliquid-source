use node94_gossip_reload_gates::{metadata_gate_opens, throttle_gate_opens};
use std::io::{self, BufRead};
fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let f: Vec<_> = line.split('\t').collect();
        let actual = match f[0] {
            "M" if f.len() == 7 => metadata_gate_opens(
                [
                    f[1].parse().unwrap(),
                    f[2].parse().unwrap(),
                    f[3].parse().unwrap(),
                ],
                [
                    f[4].parse().unwrap(),
                    f[5].parse().unwrap(),
                    f[6].parse().unwrap(),
                ],
            ),
            "T" if f.len() == 4 => throttle_gate_opens(
                f[1].parse().unwrap(),
                f64::from_bits(u64::from_str_radix(f[2], 16).unwrap()),
                f64::from_bits(u64::from_str_radix(f[3], 16).unwrap()),
            ),
            _ => panic!("only operation and input fields are allowed"),
        };
        println!("{}", u8::from(actual));
    }
}
