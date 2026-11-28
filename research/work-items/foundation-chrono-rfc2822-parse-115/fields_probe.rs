// Standalone offline test bridge for check_rust_fields.py.
#[path = "../../../src/node115-base/src/rfc2822.rs"]
mod rfc2822;
use rfc2822::{ParseError, ParsedFields};
use std::io::{self, BufRead};

fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let (initial, encoded) = line.split_once(' ').unwrap();
        let bytes: Vec<_> = encoded
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        let text = std::str::from_utf8(&bytes).unwrap();
        let mut fields = ParsedFields::default();
        match initial {
            "empty" => {}
            "year" => fields.year = Some(2024),
            "second" => fields.second = Some(0),
            "offset" => fields.offset_seconds = Some(-18000),
            "weekday" => fields.weekday = Some(1),
            _ => panic!("unknown preset"),
        }
        let result = match fields.parse(text) {
            Ok(tail) => format!("ok:{}", text.len() - tail.len()),
            Err(e) => format!(
                "err:{}",
                match e {
                    ParseError::OutOfRange => 0,
                    ParseError::Impossible => 1,
                    ParseError::Invalid => 3,
                    ParseError::TooShort => 4,
                }
            ),
        };
        let state = [
            fields.year,
            fields.month.map(i32::from),
            fields.day.map(i32::from),
            fields.hour_div_12.map(i32::from),
            fields.hour_mod_12.map(i32::from),
            fields.minute.map(i32::from),
            fields.second.map(i32::from),
            fields.offset_seconds,
            fields.weekday.map(i32::from),
        ];
        let values: Vec<_> = state
            .iter()
            .map(|v| v.map_or_else(|| "-".to_owned(), |n| n.to_string()))
            .collect();
        println!("{result} {}", values.join(" "));
    }
}
