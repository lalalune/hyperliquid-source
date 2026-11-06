use node115_timespec_difference::Timestamp;
use std::io::{self, BufRead, Write};
fn main() {
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let v: Vec<&str> = line.split_whitespace().collect();
        let a = Timestamp::new(v[0].parse().unwrap(), v[1].parse().unwrap());
        let b = Timestamp::new(v[2].parse().unwrap(), v[3].parse().unwrap());
        if let Some((a, b)) = a.zip(b) {
            let (tag, d) = match a.difference(b) {
                Ok(d) => ("O", d),
                Err(d) => ("E", d),
            };
            writeln!(out, "{} {} {}", tag, d.as_secs(), d.subsec_nanos()).unwrap();
        } else {
            writeln!(out, "domain").unwrap();
        }
    }
}
