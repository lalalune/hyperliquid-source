//! Input-only client. Expectations are owned by the parent comparator.
use node94_packed_coefficient::{iterate, normalize_iterate};
use std::io::{self, BufRead, Write};

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args().nth(1).ok_or("expected input path")?;
    let file = io::BufReader::new(std::fs::File::open(path)?);
    let mut output = io::BufWriter::new(io::stdout().lock());
    for line in file.lines() {
        let line = line?;
        let fields: Vec<_> = line.split('\t').collect();
        if fields.len() != 10 {
            return Err("expected ten input fields".into());
        }
        let words = fields[1..]
            .iter()
            .map(|s| u64::from_str_radix(s, 16))
            .collect::<Result<Vec<_>, _>>()?;
        let r = match fields[0] {
            "0" => iterate(words[0], words[4], words[8], words[1], words[5]),
            "1" => normalize_iterate(
                [words[0], words[1], words[2], words[3]],
                [words[4], words[5], words[6], words[7]],
                words[8],
            ),
            _ => return Err("invalid entry selector".into()),
        };
        let values = [
            r.rax, r.rbx, r.rcx, r.rdx, r.rbp, r.r8, r.r9, r.r10, r.r11, r.r12, r.r13, r.r14, r.r15,
        ];
        for (index, word) in values.iter().enumerate() {
            if index != 0 {
                write!(output, ",")?;
            }
            write!(output, "{word:016x}")?;
        }
        writeln!(output)?;
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
