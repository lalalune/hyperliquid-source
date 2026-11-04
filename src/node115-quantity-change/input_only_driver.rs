//! Input-only logical word records. Expected observations are not received.
use node115_quantity_change::{entry, post_lookup, Boundary, Notification};
use std::io::{self, Read};
include!("../../research/work-items/RE-004-quantity-change-115/client_fixture.rs");

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let mut input = String::new();
    io::stdin()
        .read_to_string(&mut input)
        .map_err(|e| e.to_string())?;
    let mut output = Vec::new();
    for line in input.lines() {
        let words: Result<Vec<u64>, _> = line.split('\t').map(str::parse).collect();
        output.push(evaluate_row(&words.map_err(|e| format!("{e}"))?).map_err(str::to_string)?);
    }
    for line in output {
        println!("{line}");
    }
    Ok(())
}
