use node94_flag_or_family::{Family, apply};
use std::io::{Read, Write};
fn word(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes.try_into().unwrap())
}
fn main() {
    let mut data = Vec::new();
    std::io::stdin().read_to_end(&mut data).unwrap();
    if data.len() % 40 != 0 {
        eprintln!("partial flag-or input");
        std::process::exit(2);
    }
    if data
        .chunks_exact(40)
        .any(|r| word(&r[..8]) > 2 || word(&r[32..40]) > u64::from(u32::MAX))
    {
        eprintln!("invalid flag-or descriptor");
        std::process::exit(2);
    }
    let mut output = Vec::with_capacity(data.len() / 40 * 32);
    for r in data.chunks_exact(40) {
        let family = match word(&r[..8]) {
            0 => Family::Entry15625e0,
            1 => Family::Entry1566100,
            _ => Family::Entry1568bb0,
        };
        let mut field = word(&r[32..40]) as u32;
        let result = apply(
            family,
            word(&r[8..16]),
            word(&r[16..24]),
            word(&r[24..32]),
            &mut field,
        );
        for v in [
            result.rax,
            result.rcx,
            result.store_address,
            u64::from(field),
        ] {
            output.extend_from_slice(&v.to_le_bytes());
        }
    }
    std::io::stdout().write_all(&output).unwrap();
}
