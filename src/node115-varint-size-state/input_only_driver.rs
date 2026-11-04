use node115_varint_size_state::{count_u32, count_u64};
use std::io::{self, BufRead};

fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let f: Vec<_> = line.split('\t').collect();
        assert_eq!(f.len(), 4, "inputs only");
        let which: u8 = f[0].parse().unwrap();
        let value: u64 = f[1].parse().unwrap();
        let mut counter = f[2].parse().unwrap();
        let flag: u8 = f[3].parse().unwrap();
        assert!(
            which == 0 || flag == 0,
            "only the qualified RCX ABI has a raw mode"
        );
        let result = match which {
            0 | 3 | 4 => count_u64(value, &mut counter),
            1 | 2 => count_u32(u32::try_from(value).unwrap(), &mut counter),
            _ => panic!("unknown qualified owner"),
        };
        let route = if result.is_ok() { "O" } else { "P" };
        println!("{route}\t{counter}");
    }
}
