//! Input-only comparison client: never opens fixture or expected-output files.
use node94_bit_writer_drain::{State, drain, project};
use std::io::{self, BufRead, BufWriter, Write};

fn main() {
    let mut out = BufWriter::new(io::stdout().lock());
    for line in io::stdin().lock().lines() {
        let line = line.expect("input line");
        let fields: Vec<_> = line.split('\t').collect();
        assert_eq!(fields.len(), 5);
        let state = State {
            counter: u32::from_str_radix(fields[1], 16).expect("counter bits") as i32,
            accumulator: u16::from_str_radix(fields[2], 16).expect("accumulator"),
            position: u64::from_str_radix(fields[3], 16).expect("position"),
        };
        let mut buffer = Vec::new();
        if fields[4] != "-" {
            assert_eq!(fields[4].len() % 2, 0);
            for index in (0..fields[4].len()).step_by(2) {
                buffer.push(u8::from_str_radix(&fields[4][index..index + 2], 16).expect("byte"));
            }
        }
        let projected = project(state);
        let mut applied = state;
        let answer = drain(&mut applied, &mut buffer);
        let (status, returned) = match answer {
            Ok(rax) => ("S", format!("{rax:016x}")),
            Err(_) => ("E", "-".repeat(16)),
        };
        let bytes = if buffer.is_empty() {
            "-".to_owned()
        } else {
            buffer
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        };
        writeln!(out, "{}\t{}\t{:02x}{:02x}\t{:08x}\t{:04x}\t{:016x}\t{:016x}\t{}\t{:08x}\t{:04x}\t{:016x}\t{}\t{}",
            fields[0], projected.emitted_len, projected.emitted[0], projected.emitted[1],
            projected.next.counter as u32, projected.next.accumulator, projected.next.position,
            projected.rax, status, applied.counter as u32, applied.accumulator,
            applied.position, returned, bytes).expect("write output");
    }
}
