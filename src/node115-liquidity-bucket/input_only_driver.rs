use node115_liquidity_bucket::{project, Route};
use std::io::{self, Read, Write};
fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).unwrap();
    let mut output = io::BufWriter::new(io::stdout().lock());
    for line in input.lines() {
        let f: Vec<u64> = line.split('\t').map(|v| v.parse().unwrap()).collect();
        assert_eq!(f.len(), 5);
        assert!(f[0] < 3);
        let mut previous = f[4];
        match project(u8::try_from(f[1]).unwrap(), f[2], f[3], &mut previous) {
            Route::DirectHandoff => writeln!(output, "D").unwrap(),
            Route::ZeroDivisorBoundary => writeln!(output, "Z").unwrap(),
            Route::Timed { bucket, active } => {
                writeln!(output, "T\t{bucket}\t{previous}\t{}", u8::from(active)).unwrap()
            }
        }
    }
}
