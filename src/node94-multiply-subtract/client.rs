//! Input-only separately linked client; expected outputs are never supplied.
use node94_multiply_subtract::{subtract_narrow, subtract_wide};
use std::io::{self, Read};

fn main() {
    let mut text = String::new();
    io::stdin().read_to_string(&mut text).unwrap();
    for line in text.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        assert_eq!(fields.len(), 8);
        let values: Vec<_> = fields[2..]
            .iter()
            .map(|field| u64::from_str_radix(field, 16).unwrap())
            .collect();
        match fields[0] {
            "w" => {
                let result = subtract_wide(
                    [values[0], values[1], values[2]],
                    [values[3], values[4]],
                    values[5],
                );
                println!(
                    "{}\t{:016x},{:016x},{:016x}\t{:016x}",
                    fields[1],
                    result.words[0],
                    result.words[1],
                    result.words[2],
                    result.return_value
                );
            }
            "n" => {
                let result = subtract_narrow(values[0], values[3], values[5]);
                println!(
                    "{}\t{:016x},{:016x}\t{:016x}",
                    fields[1], result.words[0], result.words[1], result.return_value
                );
            }
            _ => panic!("unknown operation"),
        }
    }
}
