use node115_gossip_address_vector::{Error, ReadError, decode_prefix};
use std::io::{self, BufRead};
fn error(e: Error) -> String {
    match e {
        Error::Read(ReadError::Limit) => "limit".into(),
        Error::Read(ReadError::UnexpectedEnd { additional }) => format!("end:{additional}"),
        Error::Read(ReadError::Invalid {
            expected_raw,
            found_raw,
        }) => format!("invalid:{expected_raw}:{found_raw}"),
        Error::InvalidVariant(n) => format!("variant:{n}"),
        Error::InvalidBool => "bool".into(),
        Error::Refund => "refund".into(),
        Error::Allocation => "allocation".into(),
    }
}
fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let p: Vec<_> = line.split('\t').collect();
        let mode: u8 = p[0].parse().unwrap();
        let charged = p[1].parse().unwrap();
        let limit = p[2].parse().unwrap();
        let bytes: Vec<u8> = if p[3] == "-" {
            vec![]
        } else {
            p[3].as_bytes()
                .chunks_exact(2)
                .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
                .collect()
        };
        let o = decode_prefix(&bytes, if mode == 1 { Some(limit) } else { None }, charged);
        let val = match o.result {
            Ok(v) => format!(
                "ok:{}",
                v.iter()
                    .map(|r| format!(
                        "{}:{}:{}",
                        r.fixed.to_le_bytes()[..4]
                            .iter()
                            .map(|b| format!("{b:02x}"))
                            .collect::<String>(),
                        u8::from(r.flag),
                        r.value
                    ))
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            Err(e) => error(e),
        };
        println!("{}|{}|{}", val, bytes.len() - o.remaining.len(), o.charged);
    }
}
