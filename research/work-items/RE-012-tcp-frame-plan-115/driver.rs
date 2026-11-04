use std::io::{self, Read, Write};
fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).unwrap();
    let mut out = io::BufWriter::new(io::stdout().lock());
    for line in input.lines() {
        let mut fields = line.split_whitespace();
        let hex = fields.next().unwrap();
        assert_eq!(hex.len(), 10);
        let mut bytes = [0; 5];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).unwrap();
        }
        let limit = fields.next().unwrap().parse().unwrap();
        let completed = fields.next().unwrap().parse().unwrap();
        assert!(fields.next().is_none());
        let header = projection::decode_header(&bytes);
        match projection::admit(header, limit) {
            Err(_) => writeln!(out, "0 {} 0 0 0 0", header.payload_len).unwrap(),
            Ok(plan) => {
                let chunk = projection::next_chunk(plan.payload_len, completed);
                let (start, end) = chunk.unwrap_or((0, 0));
                writeln!(
                    out,
                    "1 {} {} {} {} {}",
                    plan.payload_len,
                    u8::from(plan.decompress_after_read),
                    u8::from(chunk.is_some()),
                    start,
                    end
                )
                .unwrap();
            }
        }
    }
}
