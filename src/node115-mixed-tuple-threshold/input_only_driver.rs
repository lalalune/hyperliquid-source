use node115_mixed_tuple_threshold::select;
use std::io::{self, BufRead, Write};
fn main() {
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    for line in io::stdin().lock().lines() {
        let row: Vec<u64> = line
            .unwrap()
            .split(',')
            .map(|s| s.parse().unwrap())
            .collect();
        assert_eq!(row.len(), 10);
        assert!(row[0] < 3);
        let a = row[1..4].map_words();
        let b = row[4..7].map_words();
        writeln!(out, "{}", select(a, b, row[7], row[8], row[9])).unwrap();
    }
}
trait Words {
    fn map_words(&self) -> [u32; 3];
}
impl Words for [u64] {
    fn map_words(&self) -> [u32; 3] {
        [
            self[0].try_into().unwrap(),
            self[1].try_into().unwrap(),
            self[2].try_into().unwrap(),
        ]
    }
}
