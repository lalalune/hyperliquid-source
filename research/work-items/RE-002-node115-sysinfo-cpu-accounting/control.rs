use std::collections::BTreeMap;
use std::io::{self, BufRead};

struct Process {
    utime: u64,
    stime: u64,
    old_utime: u64,
    old_stime: u64,
    cpu_usage: f32,
    tasks: BTreeMap<u32, Process>,
}

include!("public_function.rs");

fn process(fields: &[u64]) -> Process {
    Process {
        old_utime: fields[0],
        old_stime: fields[1],
        utime: fields[2],
        stime: fields[3],
        cpu_usage: f32::from_bits(fields[4] as u32),
        tasks: BTreeMap::new(),
    }
}

fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let row: Vec<u64> = line.split_whitespace().map(|s| s.parse().unwrap()).collect();
        let mut root = process(&row[..5]);
        let mut child = process(&row[5..10]);
        child.tasks.insert(1, process(&row[10..15]));
        root.tasks.insert(1, child);
        compute_cpu_usage(&mut root, f32::from_bits(row[15] as u32), f32::from_bits(row[16] as u32));
        let child = &root.tasks[&1];
        println!("{} {} {}", root.cpu_usage.to_bits(), child.cpu_usage.to_bits(), child.tasks[&1].cpu_usage.to_bits());
    }
}
