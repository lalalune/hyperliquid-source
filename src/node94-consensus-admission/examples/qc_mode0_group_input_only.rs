//! Input-only field projection driver; expected fixtures are external.
use node94_consensus_admission::qc_mode0_group::{read_mode0_group, Mode0GroupOutcome};
use std::io::{self, BufRead};

fn unhex(s: &str) -> Vec<u8> {
    if s == "-" { return vec![]; }
    assert_eq!(s.len() % 2, 0);
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
        assert_eq!(f.len(), 5);
        let mut charge: u64 = f[2].parse().unwrap();
        let wire = unhex(f[4]);
        let mut input = wire.as_slice();
        let outcome = read_mode0_group(f[1].parse().unwrap(), &mut charge, f[3].parse().unwrap(), &mut input);
        let advance = wire.len() - input.len();
        match outcome {
            Mode0GroupOutcome::Complete(words) => {
                let bytes: Vec<_> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
                println!("{}\t{}\t{}\t{}\t{}\t0\t-\t-\t-\t-\t-\t{}",
                         f[0], charge, advance, input.len(), hex(input), hex(&bytes));
            }
            Mode0GroupOutcome::Incomplete { .. } => {
                let (tag, kind, need) = outcome.observed_short_fields().unwrap();
                // Driver-only projection of the proven shared row forwarding.
                let row_tag = tag;
                let row_kind = kind;
                let row_need = need;
                println!("{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t-",
                         f[0], charge, advance, input.len(), hex(input), tag, kind, need,
                         row_tag, row_kind, row_need);
            }
            Mode0GroupOutcome::OutsideDomain => {
                println!("{}\t{}\t{}\t{}\t{}\t-\t-\t-\t-\t-\t-\t-",
                         f[0], charge, advance, input.len(), hex(input));
            }
        }
    }
}
