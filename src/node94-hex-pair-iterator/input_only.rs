//! Separate raw-input-only external client. No expectation or file access.
use std::io::{self, BufRead};
use node94_hex_pair_iterator::HexPairs;

fn unhex(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0);
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex byte")).collect()
}
fn hex(bytes: &[u8]) -> String { bytes.iter().map(|v| format!("{v:02x}")).collect() }
fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.expect("input line");
        let fields: Vec<_> = line.split('|').collect();
        assert_eq!(fields.len(), 4, "four raw input fields");
        let id = fields[0];
        assert!(id.bytes().all(|b| b.is_ascii_alphanumeric()));
        let bytes = unhex(fields[1]);
        let text = std::str::from_utf8(&bytes).expect("qualified valid UTF-8 input");
        let mut output: [u8; 16] = unhex(fields[2]).try_into().expect("initial16 bytes");
        let calls: usize = fields[3].parse().expect("call count");
        let mut iterator = HexPairs::new(text);
        for ordinal in 1..=calls {
            let original = output.as_ptr();
            let returned = iterator.next_into(&mut output);
            let same = u8::from(std::ptr::eq(original, returned.as_ptr()));
            println!("{id}|{ordinal}|{}|{}|{}|{}|{same}", hex(&output), iterator.cursor(), iterator.consumed(), u8::from(iterator.halted()));
        }
    }
}
