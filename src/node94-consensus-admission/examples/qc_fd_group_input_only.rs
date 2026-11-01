//! Input-only TSV driver. No expectations, native binary, or fixture paths.
use node94_consensus_admission::qc_fd_group::read_mode1_fd_group;
use std::io::{self, BufRead};

fn unhex(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0);
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "-".to_owned();
    }
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let fields: Vec<_> = line.split('\t').collect();
        if fields[0] == "id" {
            continue;
        }
        assert_eq!(fields.len(), 5);
        let mut charge: u64 = fields[1].parse().unwrap();
        let limit: u64 = fields[2].parse().unwrap();
        let wire = unhex(fields[3]);
        let mut input = wire.as_slice();
        let mut output: [u8; 40] = unhex(fields[4]).try_into().unwrap();
        assert!(read_mode1_fd_group(&mut charge, limit, &mut input, &mut output));
        println!(
            "{}\t{}\t{}\t{}\t{}",
            fields[0], charge, wire.len() - input.len(), hex(input), hex(&output)
        );
    }
}
