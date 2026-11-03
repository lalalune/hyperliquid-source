use std::io::{self, Read, Write};
fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).unwrap();
    let mut output = io::BufWriter::new(io::stdout().lock());
    for line in input.lines() {
        let f: Vec<u64> = line.split('\t').map(|v| v.parse().unwrap()).collect();
        assert_eq!(f.len(), 4);
        match node115_price_core::quote_from_rounded_word(f[0], f[1], f[2], f[3]) {
            Ok(value) => writeln!(output, "O\t{value}").unwrap(),
            Err(_) => writeln!(output, "E").unwrap(),
        }
    }
}
