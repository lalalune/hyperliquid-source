use node115_fee_window_scan::scan;
use std::io::{self, BufRead, Write};
fn main() {
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let (width, words) = line.split_once('\t').unwrap();
        let width = width.parse().unwrap();
        let words: Vec<u64> = if words == "-" {
            Vec::new()
        } else {
            words.split(',').map(|w| w.parse().unwrap()).collect()
        };
        let result = scan(&words, width).expect("qualified corpus");
        writeln!(
            out,
            "[{},{},{}]",
            u8::from(result.found),
            result.consumed,
            result.remaining
        )
        .unwrap();
    }
}
