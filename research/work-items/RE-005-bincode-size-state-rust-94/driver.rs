extern crate hl_bincode_varint;
use hl_bincode_varint::{count_u32, count_u64};
use std::io::{self, BufRead};
fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let f: Vec<_> = line.split('\t').collect();
        assert_eq!(f.len(), 4);
        let owner: u8 = f[0].parse().unwrap();
        let value: u64 = f[1].parse().unwrap();
        let mut counter: u64 = f[2].parse().unwrap();
        let _: u8 = f[3].parse().unwrap();
        let result = match owner {
            0 => count_u32(u32::try_from(value).unwrap(), &mut counter),
            1 | 2 => count_u64(value, &mut counter),
            _ => panic!("invalid owner"),
        };
        // Own comparison protocol, not the original result-object layout.
        if result.is_ok() {
            println!("O\t{counter}\t8");
        } else {
            println!("P\t{counter}\t85");
        }
    }
}
