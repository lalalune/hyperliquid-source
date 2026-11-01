use node94_chunk_equality_family::{Pattern, compare};
use std::io::{Read, Write};
fn main() {
    let mut input = Vec::new();
    std::io::stdin().read_to_end(&mut input).unwrap();
    if input.len() % 32 != 0 {
        eprintln!("partial chunk-equality input");
        std::process::exit(2);
    }
    if input
        .chunks_exact(32)
        .any(|r| u64::from_le_bytes(r[..8].try_into().unwrap()) >= 12)
    {
        eprintln!("invalid pattern input");
        std::process::exit(2);
    }
    let mut output = Vec::with_capacity(input.len() / 32 * 24);
    for row in input.chunks_exact(32) {
        let index = u64::from_le_bytes(row[..8].try_into().unwrap()) as u8;
        let object = u64::from_le_bytes(row[8..16].try_into().unwrap());
        let chunk: &[u8; 16] = row[16..32].try_into().unwrap();
        let r = compare(Pattern::from_index(index).unwrap(), chunk, object);
        for value in [r.rax, r.rdx, r.rcx] {
            output.extend_from_slice(&value.to_le_bytes());
        }
    }
    std::io::stdout().write_all(&output).unwrap();
}
