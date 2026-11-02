extern crate node94_checkpoint_retention;
use node94_checkpoint_retention::{decide, retained_row};
use std::io::{self, BufRead};

fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let words: Vec<_> = line.split_whitespace().collect();
        match words[0] {
            "D" => {
                let r: Vec<u64> = words[1..].iter().map(|x| x.parse().unwrap()).collect();
                assert_eq!(r.len(), 5);
                let d = decide(u8::try_from(r[0]).unwrap(), r[1], r[2], r[3], r[4]);
                println!("{} {}", u8::from(d.keep), u8::from(d.diagnostic_requested));
            }
            "R" => {
                assert_eq!(words.len(), 6);
                let hex = words[5];
                assert_eq!(hex.len(), 64);
                let mut row = [0; 32];
                for (out, raw) in row.iter_mut().zip(hex.as_bytes().chunks_exact(2)) {
                    *out = u8::from_str_radix(std::str::from_utf8(raw).unwrap(), 16).unwrap();
                }
                match retained_row(
                    row,
                    words[1].parse().unwrap(),
                    words[2].parse().unwrap(),
                    words[3].parse().unwrap(),
                    words[4].parse().unwrap(),
                ) {
                    None => println!("N"),
                    Some(row) => {
                        for byte in row {
                            print!("{byte:02x}");
                        }
                        println!();
                    }
                }
            }
            _ => panic!("bad input kind"),
        }
    }
}
