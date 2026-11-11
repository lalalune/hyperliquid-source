use node115_iso_week_date::{Weekday, from_iso_week};
use std::io::{self, BufRead, Write};
fn main() {
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let v: Vec<&str> = line.split_whitespace().collect();
        match from_iso_week(
            v[0].parse().unwrap(),
            v[1].parse().unwrap(),
            Weekday::from_monday_index(v[2].parse().unwrap()).unwrap(),
        ) {
            Ok(Some(d)) => {
                writeln!(out, "D {} {} {} {}", d.packed, d.year, d.ordinal, d.flags).unwrap()
            }
            Ok(None) => writeln!(out, "N").unwrap(),
            Err(_) => writeln!(out, "overflow").unwrap(),
        }
    }
}
