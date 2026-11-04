//! Only input bytes are received; expected observations are never read.
use node115_symbol_prefix::{observe, PrefixObservation};
use std::io::{self, Read};
include!("../../research/work-items/RE-001-symbol-prefix-115/client_fixture.rs");

fn main() {
    let result = run();
    if let Err(message) = result {
        eprintln!("{message}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let mut input = String::new();
    io::stdin()
        .read_to_string(&mut input)
        .map_err(|e| e.to_string())?;
    let mut results = Vec::new();
    for line in input.lines() {
        let raw = decode_hex(line).map_err(str::to_string)?;
        results.push(render(observe(&raw)));
    }
    for line in results {
        println!("{line}");
    }
    Ok(())
}
