use node115_tree_next::{advance, Node, Outcome, State};
use std::io::{self, Read, Write};
#[path = "../../research/work-items/RE-014-tree-next-115/client_fixture.rs"]
mod fixture;
fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).unwrap();
    let mut out = io::BufWriter::new(io::stdout().lock());
    for line in input.lines() {
        let fields: Vec<_> = line.split('\t').collect();
        writeln!(out, "{}", fixture::run(&fields)).unwrap();
    }
}
