#![forbid(unsafe_code)]

use node94_u128_binary64::binary64_bits;
use std::io::{self, Write};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os();
    let _program = args.next();
    let stimulus = args.next().ok_or("one stimulus path required")?;
    if args.next().is_some() {
        return Err("only one stimulus path is accepted".into());
    }
    let input = std::fs::read_to_string(stimulus)?;
    let mut output = io::BufWriter::new(io::stdout().lock());
    for line in input.lines() {
        let (id, word) = line.split_once('|').ok_or("missing case separator")?;
        if id.is_empty()
            || id.len() > 64
            || !id.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
            || word.len() != 32
            || !word.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            return Err("invalid case id or complete lowercase128-bit word".into());
        }
        let n = u128::from_str_radix(word, 16)?;
        writeln!(output, "{id}|{:016x}", binary64_bits(n))?;
    }
    output.flush()?;
    Ok(())
}
