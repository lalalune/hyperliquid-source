use node115_time_producer::{Error, from_ce_day, from_clock_read};
use std::io::{self, BufRead, Write};
fn main() {
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let v: Vec<&str> = line.split_whitespace().collect();
        if v[0] == "D" {
            match from_ce_day(v[1].parse().unwrap()) {
                Some(d) => {
                    writeln!(out, "D {} {} {} {}", d.packed, d.year, d.ordinal, d.flags).unwrap()
                }
                None => writeln!(out, "N").unwrap(),
            }
        } else {
            match from_clock_read(v[1].parse().unwrap(), v[2].parse().unwrap()) {
                Ok(t) => writeln!(
                    out,
                    "T {} {} {} {} {} {}",
                    t.date.packed,
                    t.date.year,
                    t.date.ordinal,
                    t.date.flags,
                    t.seconds_of_day,
                    t.nanoseconds
                )
                .unwrap(),
                Err(e) => writeln!(
                    out,
                    "{}",
                    match e {
                        Error::Nanoseconds => "nanos",
                        Error::BeforeEpoch => "before",
                        Error::DateRange => "range",
                    }
                )
                .unwrap(),
            }
        }
    }
}
