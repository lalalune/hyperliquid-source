extern crate node115_gossip_rpc_request;
use node115_gossip_rpc_request::{decode_prefix, Error, ReadError, Request};
use std::io::{self, BufRead, Write};
fn main() {
    let mut out = io::BufWriter::new(io::stdout().lock());
    for line in io::stdin().lock().lines() {
        let line = line.expect("input read");
        let fields: Vec<_> = line.split('\t').collect();
        assert_eq!(fields.len(), 4, "input-only mode/count/limit/hex");
        let charged = fields[1].parse::<u64>().expect("count");
        let limit = match fields[0] { "0" => None, "1" => Some(fields[2].parse::<u64>().expect("limit")), _ => panic!("mode") };
        let hex = fields[3];
        let bytes = if hex == "-" { Vec::new() } else {
            assert_eq!(hex.len() % 2, 0);
            (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i+2], 16).expect("hex")).collect::<Vec<_>>()
        };
        let value = decode_prefix(&bytes, limit, charged);
        let label = match value.result {
            Ok(Request::Variant0 { first, second }) => format!("v0:{first}:{second}"),
            Ok(Request::Variant1) => "v1".into(),
            Ok(Request::Variant2) => "v2".into(),
            Err(Error::InvalidVariant { index }) => format!("e5:{index}"),
            Err(Error::Read(ReadError::UnexpectedEnd { additional })) => format!("e0:{additional}"),
            Err(Error::Read(ReadError::Limit)) => "e2".into(),
            Err(Error::Read(ReadError::Invalid { expected_raw, found_raw })) => format!("e3:{expected_raw}:{found_raw}"),
        };
        writeln!(out, "{label}|{}|{}", bytes.len()-value.remaining.len(), value.charged).expect("output");
    }
}
