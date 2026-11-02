use std::io::{self, BufRead};
use node94_cpu_cache_projection::{cache_value, quota_cpus};

fn optional(value: Option<u64>) -> String {
    value.map_or_else(|| "none".to_owned(), |n| n.to_string())
}

fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.expect("input line");
        let values: Vec<u64> = line.split_whitespace()
            .map(|part| part.parse().expect("unsigned input")).collect();
        assert_eq!(values.len(), 3, "expected quota, period and logical count");
        let (q, p, logical) = (values[0], values[1], values[2]);
        if p == 0 {
            println!("none none none none none");
        } else {
            let qf = q as f64;
            let pf = p as f64;
            println!("{:016x} {:016x} {:016x} {} {}", qf.to_bits(), pf.to_bits(),
                     (qf / pf).to_bits(), optional(quota_cpus(q, p)),
                     optional(cache_value(q, p, logical)));
        }
    }
}
