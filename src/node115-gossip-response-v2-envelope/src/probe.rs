use node115_gossip_response_v2_envelope::{Error, ReadError, Selection, decode_prefix};
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
            Ok(Selection::OtherVariant(n)) => format!("other:{n}"),
            Ok(Selection::Variant2(None)) => "ok:none".into(),
            Ok(Selection::Variant2(Some(r))) => format!(
                "ok:some:{}:{}:{}:{}:{}",
                r.fields[0],
                r.fields[1],
                r.fields[2],
                r.fields[3],
                r.optional_value.map_or("-".into(), |n| n.to_string())
            ),
            Err(Error::Read(e)) => read_error(e),
            Err(Error::InvalidVariant { index }) => format!("variant:{index}"),
            Err(Error::InvalidOuterOption { found }) => format!("outer:{found}"),
            Err(Error::Record(node115_gossip_response_record::Error::Read(e))) => read_error(e),
            Err(Error::Record(node115_gossip_response_record::Error::InvalidOption { found })) => {
                format!("inner:{found}")
            }
        };
        println!(
            "{}|{}|{}",
            value,
            bytes.len() - o.remaining.len(),
            o.charged
        );
    }
}
