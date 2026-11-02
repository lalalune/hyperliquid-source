use std::io::{self, Read, Write};
fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).unwrap();
    let mut out = io::BufWriter::new(io::stdout().lock());
    for line in input.lines() {
        let mut fields = line.split_whitespace();
        let p = fields.next().unwrap().parse().unwrap();
        let a = fields.next().unwrap().parse().unwrap();
        let c: u8 = fields.next().unwrap().parse().unwrap();
        let w = fields.next().unwrap().parse().unwrap();
        let b = projection::bracket(p, a, c != 0);
        let (saved, cleared) = projection::saved_flags(w);
        writeln!(
            out,
            "{} {} {} {} {}",
            b.route as u8,
            b.body_state.map(i16::from).unwrap_or(-1),
            b.restored.map(i16::from).unwrap_or(-1),
            saved,
            cleared
        )
        .unwrap();
        assert!(fields.next().is_none());
    }
}
