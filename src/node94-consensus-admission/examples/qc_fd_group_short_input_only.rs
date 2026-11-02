//! Input-only driver for qualified active fields; no expected-data file access.
use node94_consensus_admission::qc_fd_group::{read_mode1_fd_group_outcome, FdGroupOutcome};
use std::io::{self, BufRead};

fn unhex(s: &str) -> Vec<u8> {
    if s == "-" { return vec![]; }
    s.as_bytes().chunks_exact(2)
        .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap()).collect()
}
fn hex(bytes: &[u8]) -> String {
    if bytes.is_empty() { return "-".to_owned(); }
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let f: Vec<_> = line.split('\t').collect();
        if f[0] == "id" { continue; }
        assert_eq!(f.len(), 4);
        let mut charge: u64 = f[1].parse().unwrap();
        let wire = unhex(f[3]);
        let mut input = wire.as_slice();
        let outcome = read_mode1_fd_group_outcome(&mut charge, f[2].parse().unwrap(), &mut input);
        let advance = wire.len() - input.len();
        match outcome {
            FdGroupOutcome::Complete(words) => {
                let bytes: Vec<_> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
                println!("{}\t{}\t{}\t{}\t{}\t0\t-\t-\t-\t-\t-\t{}",
                         f[0], charge, advance, input.len(), hex(input), hex(&bytes));
            }
            FdGroupOutcome::Incomplete { .. } => {
                let (tag, kind, need) = outcome.observed_short_fields().unwrap();
                // Project the row forwarding of these active fields only.
                let row_tag = tag;
                let row_kind = kind;
                let row_need = need;
                println!("{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t-",
                         f[0], charge, advance, input.len(), hex(input), tag, kind, need,
                         row_tag, row_kind, row_need);
            }
            FdGroupOutcome::OutsideDomain => panic!("outside qualified input domain"),
        }
    }
}
