use node115_spot_decimal::{convert, Observation};
use std::io::{self, Read, Write};
include!("../../research/work-items/RE-004-spot-decimal-115/client_fixture.rs");
fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).unwrap();
    let mut output = io::BufWriter::new(io::stdout().lock());
    for line in input.lines() {
        writeln!(output, "{}", adapt(line)).unwrap();
    }
}
