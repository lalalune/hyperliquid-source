//! Input-only group-state driver; expected outputs are external.
use node94_consensus_admission::qc_mode1_group::{read_mode1_group, Mode1GroupOutcome};
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
        assert_eq!(f.len(), 6);
        let mut charge: u64 = f[2].parse().unwrap();
        let wire = unhex(f[4]);
        let mut group: [u8; 40] = unhex(f[5]).try_into().unwrap();
        let mut input = wire.as_slice();
        let outcome = read_mode1_group(f[1].parse().unwrap(), &mut charge, f[3].parse().unwrap(), &mut input);
        let memory = if outcome.write_result_view(&mut group) { hex(&group) } else { "-".to_owned() };
        let advance = wire.len() - input.len();
        match outcome {
            Mode1GroupOutcome::Complete(words) => {
                let values: Vec<_> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
                println!("{}\t{}\t{}\t{}\t{}\t0\t-\t-\t-\t-\t-\t{}\t{}",
                         f[0], charge, advance, input.len(), hex(input), hex(&values), memory);
            }
            Mode1GroupOutcome::Incomplete { .. } | Mode1GroupOutcome::BudgetDenied => {
                let (tag, kind, need) = outcome.observed_error_fields().unwrap();
                let need = need.map_or_else(|| "-".to_owned(), |n| n.to_string());
                // Driver-only active row forwarding; denial need stays unknown.
                let row_tag = 1u64; // The native row writes its own tag1.
                let row_kind = kind;
                let row_need = &need;
                println!("{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t-\t{}",
                         f[0], charge, advance, input.len(), hex(input), tag, kind, need,
                         row_tag, row_kind, row_need, memory);
            }
            Mode1GroupOutcome::OutsideDomain => {
                println!("{}\t{}\t{}\t{}\t{}\t-\t-\t-\t-\t-\t-\t-\t-",
                         f[0], charge, advance, input.len(), hex(input));
            }
        }
    }
}
