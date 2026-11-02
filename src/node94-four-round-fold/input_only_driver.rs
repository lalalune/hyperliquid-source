//! Input-only native client. Expectations are never supplied to this process.
use std::io::{self, BufRead, Write};

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args().nth(1).ok_or("expected input path")?;
    let file = std::io::BufReader::new(std::fs::File::open(path)?);
    let mut output = io::BufWriter::new(io::stdout().lock());
    for line in file.lines() {
        let line = line?;
        let words = line
            .split('\t')
            .map(|word| u64::from_str_radix(word, 16))
            .collect::<Result<Vec<_>, _>>()?;
        if words.len() != 9 {
            return Err("expected nine input words".into());
        }
        let a = [words[0], words[1], words[2], words[3]];
        let m = [words[4], words[5], words[6], words[7]];
        let r = node94_four_round_fold::fold(a, m, words[8]);
        writeln!(
            output,
            "{:016x},{:016x},{:016x},{:016x},{:016x},{:016x},{:016x},{:016x},{:016x}",
            r.rax, r.rdx, r.r9, r.r10, r.r11, r.r12, r.r13, r.r14, r.r15
        )?;
    }
    output.flush()?;
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(2);
    }
}
