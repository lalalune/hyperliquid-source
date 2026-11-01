//! Input-only client; every output delta is computed over the entire image.
use node94_cursor_prefix_step::{AccessError, ObservedRax, step};
use std::io::{self, BufRead, BufWriter, Write};

fn main() {
    let mut out = BufWriter::new(io::stdout().lock());
    for line in io::stdin().lock().lines() {
        let line = line.expect("input line");
        let fields: Vec<_> = line.split('\t').collect();
        assert_eq!(fields.len(), 4);
        let base = u64::from_str_radix(fields[1], 16).expect("base");
        let state = usize::from_str_radix(fields[2], 16).expect("state offset");
        let mut image = Vec::new();
        if fields[3] != "-" {
            assert_eq!(fields[3].len() % 2, 0);
            for index in (0..fields[3].len()).step_by(2) {
                image.push(u8::from_str_radix(&fields[3][index..index + 2], 16).expect("byte"));
            }
        }
        let old = image.clone();
        let status = match step(&mut image, base, state) {
            Ok(ObservedRax::Unchanged) => "U".to_owned(),
            Ok(ObservedRax::Value(rax)) => format!("V:{rax:016x}"),
            Err(AccessError::ImageRange) => "E:R".to_owned(),
            Err(AccessError::StateBounds) => "E:S".to_owned(),
            Err(AccessError::PrefixBounds) => "E:P".to_owned(),
        };
        let changes: Vec<_> = old
            .iter()
            .zip(&image)
            .enumerate()
            .filter(|(_, (old, new))| old != new)
            .map(|(index, (_, new))| format!("{index:x}:{new:02x}"))
            .collect();
        let changes = if changes.is_empty() {
            "-".to_owned()
        } else {
            changes.join(",")
        };
        writeln!(out, "{}\t{}\t{}", fields[0], status, changes).expect("output");
    }
}
