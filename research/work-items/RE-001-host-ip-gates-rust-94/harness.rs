use std::io::{self, Read, Write};
fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).unwrap();
    let mut out = io::BufWriter::new(io::stdout().lock());
    for line in input.lines() {
        let mut fields = line.split_whitespace();
        let n = fields.next().unwrap().parse().unwrap();
        let a = fields.next().unwrap().parse().unwrap();
        let r = fields.next().unwrap().parse().unwrap();
        let o = fields.next().unwrap().parse().unwrap();
        writeln!(
            out,
            "{} {}",
            projection::admission(n, a, r) as u8,
            u8::from(projection::probe_path(o))
        )
        .unwrap();
        assert!(fields.next().is_none());
    }
}
