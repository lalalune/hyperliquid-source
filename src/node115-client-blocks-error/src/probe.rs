use node115_client_blocks_error::{Error, ReadError, decode_prefix};
use std::io::{self, BufRead};
fn read_error(e: ReadError) -> String {
    match e {
        ReadError::Limit => "e2".into(),
        ReadError::UnexpectedEnd { additional } => format!("e0:{additional}"),
        ReadError::Invalid {
            expected_raw,
            found_raw,
        } => format!("e3:{expected_raw}:{found_raw}"),
    }
}
fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let p: Vec<&str> = line.split('\t').collect();
        let mode: u8 = p[0].parse().unwrap();
        let charged: u64 = p[1].parse().unwrap();
        let limit: u64 = p[2].parse().unwrap();
        let bytes: Vec<u8> = if p[3] == "-" {
            vec![]
        } else {
            p[3].as_bytes()
                .chunks_exact(2)
                .map(|x| u8::from_str_radix(std::str::from_utf8(x).unwrap(), 16).unwrap())
                .collect()
        };
        let o = decode_prefix(&bytes, if mode == 1 { Some(limit) } else { None }, charged);
        let value = match o.result {
            Ok(v) => match v.fields {
                Some([a, b]) => format!("ok:{}:{a}:{b}", v.index),
                None => format!("ok:{}", v.index),
            },
            Err(Error::Read(e)) => read_error(e),
            Err(Error::InvalidVariant { index }) => format!("variant:{index}"),
        };
        println!(
            "{}|{}|{}",
            value,
            bytes.len() - o.remaining.len(),
            o.charged
        );
    }
}
