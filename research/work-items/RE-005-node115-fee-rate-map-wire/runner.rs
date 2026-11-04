use node115_fee_rate_map_codec::encode_bits;
use std::io::{self, BufRead};

fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.expect("comparison input");
        let words: Vec<_> = line
            .split_whitespace()
            .map(|word| u64::from_str_radix(word, 16).expect("frozen hex word"))
            .collect();
        let encoded = encode_bits(words.try_into().expect("four frozen words"));
        for byte in encoded {
            print!("{byte:02x}");
        }
        println!();
    }
}
