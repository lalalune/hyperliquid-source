extern crate node115_gossip_response_record;
use node115_gossip_response_record::{Error, ReadError, decode_prefix};
use std::io::{self, BufRead, Write};
fn main() {
    let mut out = io::BufWriter::new(io::stdout().lock());
    for line in io::stdin().lock().lines() {
        let line = line.expect("read input");
        let fields: Vec<_> = line.split('\t').collect();
        assert_eq!(fields.len(), 4, "input only, no expected output");
        let charged = fields[1].parse::<u64>().expect("charged");
        let limit = match fields[0] {
            "0" => None,
            "1" => Some(fields[2].parse::<u64>().expect("limit")),
            _ => panic!("mode"),
        };
        let hex = fields[3];
        let bytes = if hex == "-" {
            Vec::new()
        } else {
            assert_eq!(hex.len() % 2, 0);
            (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
                .collect::<Vec<_>>()
        };
        let value = decode_prefix(&bytes, limit, charged);
        let label = match value.result {
            Ok(record) => format!(
                "ok:{}:{}:{}:{}:{}",
                record.fields[0],
                record.fields[1],
                record.fields[2],
                record.fields[3],
                record
                    .optional_value
                    .map_or_else(|| "-".into(), |v| v.to_string())
            ),
            Err(Error::Read(ReadError::UnexpectedEnd { additional })) => format!("e0:{additional}"),
            Err(Error::Read(ReadError::Limit)) => "e2".into(),
            Err(Error::Read(ReadError::Invalid {
                expected_raw,
                found_raw,
            })) => {
                format!("e3:{expected_raw}:{found_raw}")
            }
            Err(Error::InvalidOption { found }) => format!("e5:{found}"),
        };
        writeln!(
            out,
            "{label}|{}|{}",
            bytes.len() - value.remaining.len(),
            value.charged
        )
        .expect("output");
    }
}
