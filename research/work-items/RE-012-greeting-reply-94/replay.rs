//! Projection adapter for independently frozen mathematical fixtures.
use node94_tcp_frame::greeting::reply::{ErrorKind, HashReply, Map, MapValue, Reply, decode};
use std::io::{self, BufRead, Write};

fn unhex(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0);
    s.as_bytes()
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn value_bytes(value: &MapValue, out: &mut Vec<u8>) {
    for n in value.first.iter().chain(value.second.iter()) {
        out.extend(n.to_le_bytes());
    }
    out.push(value.last);
}
fn map_bytes(map: Map) -> Vec<u8> {
    let mut out = Vec::new();
    for (key, value) in map {
        out.extend(key);
        value_bytes(&value, &mut out);
    }
    out
}
fn main() {
    let mut out = io::BufWriter::new(io::stdout().lock());
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let fields: Vec<_> = line.split('|').collect();
        let family = fields[0];
        let limit: u64 = fields[1].parse().unwrap();
        let bytes = unhex(fields[2]);
        let base = match family {
            "records" => 24,
            "values" => 84,
            "maps" => 56,
            _ => panic!("family"),
        };
        let prefix = match family {
            "records" => 4,
            "values" => 57,
            "maps" => 36,
            _ => unreachable!(),
        };
        let (status, consumed, charged, payload) = match decode(&bytes, limit) {
            Ok(decoded) => {
                let Reply::Variant0 { hash, .. } = decoded.reply else {
                    panic!("root")
                };
                let data = match (family, hash) {
                    ("records", HashReply::Variant2(records)) => {
                        let mut data = Vec::new();
                        for record in *records {
                            data.extend(record.bytes);
                            data.extend(record.first.to_le_bytes());
                            data.extend(record.second.to_le_bytes());
                        }
                        data
                    }
                    ("values", HashReply::Variant0 { map, .. }) => {
                        let mut data = Vec::new();
                        value_bytes(map.values().next().unwrap(), &mut data);
                        data
                    }
                    ("maps", HashReply::Variant0 { map, .. }) => map_bytes(map),
                    _ => panic!("projection"),
                };
                (
                    "ok".to_string(),
                    decoded.consumed,
                    decoded.charged,
                    hex(&data),
                )
            }
            Err(f) => {
                let status = match f.kind {
                    ErrorKind::UnexpectedEnd { needed } => format!("e0:{needed}"),
                    ErrorKind::CollectionTooLong => "e1".to_string(),
                    ErrorKind::Limit => "e2".to_string(),
                    ErrorKind::InvalidIntegerType { expected, found } => {
                        format!("e3:{expected}:{found}")
                    }
                    ErrorKind::UnexpectedVariant { .. } => panic!("unexpected variant"),
                };
                (status, f.consumed, f.charged, String::new())
            }
        };
        writeln!(
            out,
            "{status}|{}|{}|{payload}",
            consumed - prefix,
            charged - base
        )
        .unwrap();
    }
}
