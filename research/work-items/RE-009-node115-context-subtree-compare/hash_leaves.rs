use node115_abci_blake3::blake3_hash;
use std::error::Error;
use std::io::{self, BufRead, Write};

fn main() -> Result<(), Box<dyn Error>> {
    let mut stdout = io::stdout().lock();
    for line in io::stdin().lock().lines() {
        let line = line?;
        if line.len() % 2 != 0 || !line.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("expected one hex-encoded leaf preimage per line".into());
        }
        let bytes = (0..line.len())
            .step_by(2)
            .map(|offset| u8::from_str_radix(&line[offset..offset + 2], 16))
            .collect::<Result<Vec<_>, _>>()?;
        write!(stdout, "0x")?;
        for byte in blake3_hash(&bytes) {
            write!(stdout, "{byte:02x}")?;
        }
        writeln!(stdout)?;
    }
    Ok(())
}
