use projection::normalize_ascii;
use std::io::{self, BufRead};

fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let raw = if line == "-" {
            Vec::new()
        } else {
            assert_eq!(line.len() % 2, 0);
            (0..line.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&line[i..i + 2], 16).unwrap())
                .collect()
        };
        match normalize_ascii(&raw) {
            None => println!("R"),
            Some(value) => {
                let text: String = value.iter().map(|b| format!("{b:02x}")).collect();
                println!("O {}", if text.is_empty() { "-" } else { &text });
            }
        }
    }
}
