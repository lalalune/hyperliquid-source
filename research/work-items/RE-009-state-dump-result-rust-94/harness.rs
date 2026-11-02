use std::io::{self, Read, Write};
fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).unwrap();
    let mut out = io::BufWriter::new(io::stdout().lock());
    for line in input.lines() {
        let mut fields = line.split_whitespace();
        let s = fields.next().unwrap().parse().unwrap();
        let status = fields.next().unwrap().parse().unwrap();
        let retained = fields.next().unwrap().parse().unwrap();
        let eax = fields.next().unwrap().parse().unwrap();
        let (route, index, words) = match projection::project(s, status, retained, eax) {
            projection::Projection::ExcludedStatus => (0, 0, [0; 3]),
            projection::Projection::IndexOutsideI32 => (1, 0, [0; 3]),
            projection::Projection::ZeroCallee { index } => (2, index, [0; 3]),
            projection::Projection::Stored { index, words } => (3, index, words),
        };
        writeln!(
            out,
            "{} {} {} {} {}",
            route, index, words[0], words[1], words[2]
        )
        .unwrap();
        assert!(fields.next().is_none());
    }
}
