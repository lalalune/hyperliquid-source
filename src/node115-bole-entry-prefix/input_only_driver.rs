//! Owned stdin adapter for frozen synthetic rows, with no native effects.
use node115_bole_entry_prefix::{prefix, Frontier, Inputs, LookupLane};
use std::io::{self, BufRead, Write};
fn list(s: &str) -> Vec<u64> {
    if s == "-" {
        Vec::new()
    } else {
        s.split(',').map(|x| x.parse().unwrap()).collect()
    }
}
fn main() {
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let v: Vec<_> = line.split('\t').collect();
        assert_eq!(v.len(), 8);
        let indices = list(v[2]);
        let occupied = list(v[3]);
        let input = Inputs {
            primary: v[0].parse().unwrap(),
            primary_len: v[1].parse().unwrap(),
            indices: &indices,
            occupied: &occupied,
            header: v[4].parse().unwrap(),
            map_len: v[5].parse().unwrap(),
            auxiliary: v[6].parse().unwrap(),
            float_bits: v[7].parse().unwrap(),
        };
        match prefix(input) {
            None => writeln!(out, "[\"D\"]").unwrap(),
            Some(Frontier::Returned2) => writeln!(out, "[\"R\"]").unwrap(),
            Some(Frontier::PrimaryGuard { index, length }) => {
                writeln!(out, "[\"P\",{index},{length}]").unwrap()
            }
            Some(Frontier::SecondaryGuard { index, length }) => {
                writeln!(out, "[\"S\",{index},{length}]").unwrap()
            }
            Some(Frontier::Lookup {
                lane,
                primary,
                secondary,
                auxiliary,
                float_bits,
            }) => writeln!(
                out,
                "[\"{}\",{primary},{secondary},{auxiliary},{float_bits}]",
                if lane == LookupLane::A { "A" } else { "B" }
            )
            .unwrap(),
        }
    }
}
