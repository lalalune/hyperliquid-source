use node94_six_word_subtract_family::{apply, Member};
use std::io::{self, Write};

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let input = std::fs::read(std::env::args_os().nth(1).ok_or("input file required")?)?;
    if input.len() % 536 != 0 {
        return Err("expected complete 536-byte input records".into());
    }
    let mut stdout = io::BufWriter::new(io::stdout().lock());
    for row in input.chunks_exact(536) {
        let fields: [u64; 19] =
            core::array::from_fn(|i| u64::from_le_bytes(row[8 * i..8 * i + 8].try_into().unwrap()));
        let member = match fields[0] {
            0 => Member::Raw,
            1 => Member::Saved,
            2 => Member::HighFirstPair,
            3 => Member::Prepared,
            _ => return Err("unknown member".into()),
        };
        let length = usize::try_from(fields[6])?;
        if length > 384 {
            return Err("image length exceeds record".into());
        }
        let mut image: [u8; 384] = row[152..].try_into().unwrap();
        let saved = fields[7..13].try_into().unwrap();
        let prepared = fields[13..19].try_into().unwrap();
        let observed = apply(
            member,
            &mut image[..length],
            fields[1],
            fields[2],
            fields[3],
            fields[4],
            fields[5],
            saved,
            prepared,
        );
        let mut output = [0_u64; 14];
        if let Some(regs) = observed {
            output[0..4].copy_from_slice(&[1, regs.rax, regs.rdx, regs.rsi]);
            output[4..8].copy_from_slice(&regs.r8_to_r11);
            output[8..14].copy_from_slice(&regs.callee);
        }
        for word in output {
            stdout.write_all(&word.to_le_bytes())?;
        }
        stdout.write_all(&image)?;
    }
    stdout.flush()?;
    Ok(())
}
