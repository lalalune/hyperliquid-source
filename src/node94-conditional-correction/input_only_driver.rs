//! Only inputs are read. The parent process retains and compares expectations.
use node94_conditional_correction::{apply, Variant};
use std::io::{self, BufRead, Write};

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args().nth(1).ok_or("expected input path")?;
    let file = io::BufReader::new(std::fs::File::open(path)?);
    let mut output = io::BufWriter::new(io::stdout().lock());
    for line in file.lines() {
        let line = line?;
        let fields: Vec<_> = line.split('\t').collect();
        if fields.len() != 6 {
            return Err("expected six input fields".into());
        }
        let variant = match fields[0] {
            "0" => Variant::Add,
            "1" => Variant::Subtract,
            "2" => Variant::AddNonzero,
            "3" => Variant::SubtractNonzero,
            _ => return Err("invalid variant".into()),
        };
        let offsets = fields[1..5]
            .iter()
            .map(|s| s.parse::<usize>())
            .collect::<Result<Vec<_>, _>>()?;
        if fields[5].len() % 2 != 0 || !fields[5].is_ascii() {
            return Err("invalid image hex".into());
        }
        let mut image = (0..fields[5].len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&fields[5][i..i + 2], 16))
            .collect::<Result<Vec<_>, _>>()?;
        let result = apply(
            &mut image, offsets[0], offsets[1], offsets[2], offsets[3], variant,
        );
        let (admitted, registers) = match result {
            Some(r) => (1, [r.rax, r.rdx, r.rsi, r.r8, r.r9, r.r10, r.r11]),
            None => (0, [0; 7]),
        };
        write!(output, "{admitted}")?;
        for word in registers {
            write!(output, ",{word:016x}")?;
        }
        write!(output, ",")?;
        for byte in image {
            write!(output, "{byte:02x}")?;
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
