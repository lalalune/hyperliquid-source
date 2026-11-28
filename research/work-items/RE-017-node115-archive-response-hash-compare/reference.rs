use std::io::{self, Read};

fn main() -> io::Result<()> {
    let mut preimage = Vec::new();
    io::stdin().read_to_end(&mut preimage)?;
    let digest = reference_hash::keccak256(&preimage);
    for byte in digest {
        print!("{byte:02x}");
    }
    println!();
    Ok(())
}
