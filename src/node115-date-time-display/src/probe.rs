use node115_date_time_display::{Date, Time, render, render_date, render_time};
use std::io::{self, BufRead, Write};
fn main() {
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let v: Vec<&str> = line.split_whitespace().collect();
        let text = match v[0] {
            "D" => Date::new(v[1].parse().unwrap(), v[2].parse().unwrap()).map(render_date),
            "T" => Time::new(v[1].parse().unwrap(), v[2].parse().unwrap()).map(render_time),
            "X" => Date::new(v[1].parse().unwrap(), v[2].parse().unwrap())
                .zip(Time::new(v[3].parse().unwrap(), v[4].parse().unwrap()))
                .map(|(d, t)| render(d, t)),
            _ => panic!("invalid probe request"),
        };
        match text {
            Some(text) => writeln!(out, "O {}", text.as_str()).unwrap(),
            None => writeln!(out, "N").unwrap(),
        }
    }
}
