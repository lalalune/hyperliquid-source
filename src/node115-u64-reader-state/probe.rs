//! Offline probe for the separately frozen mathematical corpus; no target code.
use node115_u64_reader_state::{Error, Reader};
use std::io::{self, BufRead};
fn error(error: Error) -> String {
    match error {
        Error::UnexpectedEnd { additional } => format!("e0:{additional}"),
        Error::Limit => "e2".into(),
        Error::Invalid {
            expected_raw,
            found_raw,
        } => format!("e3:{expected_raw}:{found_raw}"),
    }
}
fn evaluate(line: &str) -> String {
    let parts: Vec<_> = line.split('\t').collect();
    let charged = parts[2].parse().unwrap();
    let limit = (parts[1] == "1").then(|| parts[3].parse().unwrap());
    let input: Vec<_> = if parts[4] == "-" {
        Vec::new()
    } else {
        parts[4]
            .as_bytes()
            .chunks_exact(2)
            .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
            .collect()
    };
    let mut reader = Reader::new(&input, limit, charged);
    let result = if parts[0] == "s" {
        reader.read_u64().map(|value| format!("v:{value}"))
    } else {
        reader
            .read_four()
            .map(|v| format!("v:{},{},{},{}", v[0], v[1], v[2], v[3]))
    };
    format!(
        "{}|{}|{}",
        result.unwrap_or_else(error),
        input.len() - reader.remaining().len(),
        reader.charged()
    )
}
fn main() {
    for line in io::stdin().lock().lines() {
        println!("{}", evaluate(&line.unwrap()));
    }
}
#[cfg(test)]
mod tests {
    #[test]
    fn frozen_target_contract() {
        let corpus =
            include_str!("../../research/work-items/RE-005-node115-u64-reader-state/cases.tsv");
        for (i, line) in corpus.lines().enumerate() {
            let (input, expected) = line.rsplit_once('\t').unwrap();
            assert_eq!(super::evaluate(input), expected, "frozen row {}", i + 1);
        }
    }
}
