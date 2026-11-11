use node115_bulk_record_decoder::{Error, decode_prefix};
use std::io::{self, BufRead};
fn bytes(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    s.as_bytes()
        .chunks_exact(2)
        .map(|x| u8::from_str_radix(std::str::from_utf8(x).unwrap(), 16).unwrap())
        .collect()
}
fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let v: Vec<_> = line.split('\t').collect();
        let mut input = bytes(v[0]);
        let n: usize = v[1].parse().unwrap();
        let seed: usize = v[2].parse().unwrap();
        input.extend((0..n).map(|i| ((seed + 37 * i) % 256) as u8));
        input.extend(bytes(v[3]));
        let limit = if v[4] == "-" {
            None
        } else {
            Some(v[4].parse().unwrap())
        };
        let initial = v[5].parse().unwrap();
        let out = decode_prefix(&input, limit, initial);
        let consumed = input.len() - out.remaining.len();
        match out.result {
            Ok(r) => {
                let hex = r
                    .bytes
                    .iter()
                    .map(|x| format!("{x:02x}"))
                    .collect::<String>();
                println!(
                    "ok:{}:{}|{consumed}|{}|{hex}",
                    r.fields[0], r.fields[1], out.charged
                );
            }
            Err(e) => {
                let msg = match e {
                    Error::Limit => "limit".into(),
                    Error::UnexpectedEnd { additional } => format!("short:{additional}"),
                    Error::Invalid {
                        expected_raw,
                        found_raw,
                    } => format!("invalid:{expected_raw}:{found_raw}"),
                };
                println!("{msg}|{consumed}|{}|-", out.charged);
            }
        }
    }
}
