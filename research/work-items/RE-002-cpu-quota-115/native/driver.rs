use node115_cpu_quota::{cached_or_logical, logical_count, publish_quota, quota_stage};
use std::io::{self, BufRead};
use std::sync::atomic::{AtomicU64, Ordering};
fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let v: Vec<&str> = line.split_whitespace().collect();
        match v[0] {
            "Q" => {
                assert_eq!(v.len(), 5);
                let q = v[1].parse().unwrap();
                let p = v[2].parse().unwrap();
                let n = v[3].parse().unwrap();
                let cache = AtomicU64::new(v[4].parse().unwrap());
                let stage = quota_stage(q, p);
                let result = publish_quota(&cache, stage.as_ref(), n);
                match stage {
                    Some(s) => print!("{:016x} {:016x} {:016x} {} ", s.quota_bits, s.period_bits, s.ratio_bits, s.rounded_quota),
                    None => print!("- - - - "),
                }
                match result { Some(n) => print!("{} ", n), None => print!("- ") }
                println!("{}", cache.load(Ordering::SeqCst));
            }
            "A" => {
                let sc: i64 = v[1].parse().unwrap();
                let cache = v[2].parse().unwrap();
                let mask: Option<[u64; 16]> = if v[3] == "-" { assert_eq!(v.len(),4); None } else {
                    assert_eq!(v.len(),19);
                    Some(std::array::from_fn(|i| u64::from_str_radix(v[i+3],16).unwrap()))
                };
                println!("{} {}", logical_count(mask.as_ref(), sc), cached_or_logical(cache, mask.as_ref(), sc));
            }
            _ => panic!("invalid fixture operation"),
        }
    }
}
