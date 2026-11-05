use node115_indirect_triplet_insert::{insert, Record};
use std::io::{self, BufRead, Write};
fn main() {
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let fields: Vec<&str> = line.split('\t').collect();
        assert_eq!(fields.len(), 3);
        let k = fields[0].parse().unwrap();
        let mut records: Vec<Record> = if fields[1] == "-" {
            Vec::new()
        } else {
            fields[1]
                .split(',')
                .map(|pair| {
                    let (payload, key) = pair.split_once(':').unwrap();
                    Record {
                        payload: payload.parse().unwrap(),
                        key: key.parse().unwrap(),
                    }
                })
                .collect()
        };
        let keys: Vec<[u32; 3]> = if fields[2] == "-" {
            Vec::new()
        } else {
            fields[2]
                .split(',')
                .map(|key| {
                    let values: Vec<u32> = key.split(':').map(|s| s.parse().unwrap()).collect();
                    values.try_into().unwrap()
                })
                .collect()
        };
        let frontier = u8::from(insert(&mut records, &keys, k).is_err());
        write!(out, "[{frontier},[").unwrap();
        for (i, record) in records.iter().enumerate() {
            if i != 0 {
                write!(out, ",").unwrap();
            }
            write!(out, "[{},{}]", record.payload, record.key).unwrap();
        }
        writeln!(out, "]]").unwrap();
    }
}
