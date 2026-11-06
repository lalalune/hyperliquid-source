use node115_user_admission_prefix::{classify, Frontier, Input};
use std::io::{self, BufRead, Write};
fn decode<const N: usize>(s: &str) -> [u8; N] {
    assert_eq!(s.len(), N * 2);
    core::array::from_fn(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
pub fn evaluate_line(line: &str) -> String {
    let fields: Vec<&str> = line.split('\t').collect();
    assert_eq!(fields.len(), 10);
    let descriptor = decode::<99>(fields[0]);
    let counts: Vec<u16> = if fields[6] == "-" {
        Vec::new()
    } else {
        fields[6].split(',').map(|s| s.parse().unwrap()).collect()
    };
    let input = Input {
        descriptor: &descriptor,
        active: fields[1].parse().unwrap(),
        mode: fields[2].parse().unwrap(),
        budget: fields[3].parse().unwrap(),
        aux: fields[4].parse().unwrap(),
        height: fields[5].parse().unwrap(),
        counts: &counts,
        identity: decode(fields[7]),
        context: decode(fields[8]),
    };
    let result = classify(&input, fields[9].parse().unwrap()).expect("qualified prefix");
    let (kind, args) = match result.frontier {
        Frontier::Returned => ("R", String::new()),
        Frontier::Identity {
            encoded,
            mode,
            operation,
            peer,
            identity,
        } => (
            "I",
            format!(
                "{encoded},{mode},{operation},\"{}\",\"{}\"",
                hex(&peer),
                hex(&identity)
            ),
        ),
        Frontier::Compare {
            encoded,
            node,
            height,
            remaining_bytes,
        } => ("C", format!("{encoded},{node},{height},{remaining_bytes}")),
        Frontier::Budget {
            encoded,
            mode,
            amount,
            budget,
        } => ("B", format!("{encoded},{mode},{amount},{budget}")),
        Frontier::Operation {
            encoded,
            mode,
            context,
        } => ("O", format!("{encoded},{mode},\"{}\"", hex(&context))),
    };
    format!("[\"{kind}\",\"{}\",[{args}]]", hex(&result.output))
}
fn main() {
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    for line in io::stdin().lock().lines() {
        writeln!(out, "{}", evaluate_line(&line.unwrap())).unwrap();
    }
}
