use node115_margin_row::{
    first_selected_row, post_doubling_point, second_selected_row, Observation,
};
use std::io::{self, Read, Write};
use std::num::NonZeroU8;
include!("../../research/work-items/RE-007-margin-row-115/client_fixture.rs");
fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).unwrap();
    let mut output = io::BufWriter::new(io::stdout().lock());
    for line in input.lines() {
        writeln!(output, "{}", adapt(line)).unwrap();
    }
}
