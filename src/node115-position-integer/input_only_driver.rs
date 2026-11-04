use node115_position_integer::{project, Observation, Width};
use std::io::{self, Read, Write};
use std::num::NonZeroI64;
include!("../../research/work-items/RE-012-position-integer-115/client_fixture.rs");
fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).unwrap();
    let mut output = io::BufWriter::new(io::stdout().lock());
    for line in input.lines() {
        let fields: Vec<u64> = line.split('\t').map(|s| s.parse().unwrap()).collect();
        assert_eq!(fields.len(), 3);
        let result = project(
            NonZeroI64::new(fields[0] as i64).unwrap(),
            fields[1],
            fields[2],
        );
        writeln!(output, "{}", observation_text(result)).unwrap();
    }
}
