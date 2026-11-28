use node115_abci_blake3::Blake3Hasher;
use std::io::{self, Read, Write};

fn main() -> io::Result<()> {
    let mut hasher = Blake3Hasher::new();
    let mut input = io::stdin().lock();
    let mut buffer = [0u8; 65536];
    loop {
        let read = input.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let mut output = io::stdout().lock();
    write!(output, "0x")?;
    for byte in hasher.finalize() {
        write!(output, "{byte:02x}")?;
    }
    writeln!(output)
}
