use node94_lane_byte_reversal::reverse_lanes;
use std::io::{self, Read, Write};

fn hex(s: &str) -> u64 {
    u64::from_str_radix(s, 16).expect("hex argument")
}
fn main() {
    let mut text = String::new();
    io::stdin().read_to_string(&mut text).unwrap();
    let mut out = io::BufWriter::new(io::stdout().lock());
    for line in text.lines() {
        let fields: Vec<_> = line.split('\t').collect();
        assert_eq!(fields.len(), 6);
        let mut image = if fields[5] == "-" {
            Vec::new()
        } else {
            assert!(fields[5].len().is_multiple_of(2));
            (0..fields[5].len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&fields[5][i..i + 2], 16).unwrap())
                .collect()
        };
        let before = image.clone();
        let status = match reverse_lanes(
            &mut image,
            hex(fields[1]),
            hex(fields[2]),
            hex(fields[3]),
            hex(fields[4]),
        ) {
            Ok(value) => format!("V:{value:016x}"),
            Err(_) => "E".into(),
        };
        let delta: Vec<_> = image
            .iter()
            .enumerate()
            .filter(|(i, b)| **b != before[*i])
            .map(|(i, b)| format!("{i:x}:{b:02x}"))
            .collect();
        writeln!(
            out,
            "{}\t{}\t{}",
            fields[0],
            status,
            if delta.is_empty() {
                "-".into()
            } else {
                delta.join(",")
            }
        )
        .unwrap();
    }
}
