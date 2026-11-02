//! Input-only comparison adapter. No captured executable or native callback.

use node94_consensus_admission::qc_row_success::{
    copy_prior_success_fields, QC_ROW_RESULT_BYTES,
};
use std::fmt::Write;

fn parse_hex<const N: usize>(input: &str) -> Result<[u8; N], String> {
    if input.len() != 2 * N {
        return Err(format!("expected {N} hex bytes"));
    }
    let mut output = [0u8; N];
    for (slot, pair) in output.iter_mut().zip(input.as_bytes().chunks_exact(2)) {
        let pair = std::str::from_utf8(pair).map_err(|_| "invalid hex input")?;
        *slot = u8::from_str_radix(pair, 16)
            .map_err(|_| "invalid hex input".to_owned())?;
    }
    Ok(output)
}

fn run() -> Result<String, String> {
    let mut args = std::env::args().skip(1);
    let raw20 = parse_hex::<20>(&args.next().ok_or("missing raw20")?)?;
    let first = parse_hex::<32>(&args.next().ok_or("missing first group")?)?;
    let second = parse_hex::<32>(&args.next().ok_or("missing second group")?)?;
    let recovery = parse_hex::<1>(&args.next().ok_or("missing recovery byte")?)?[0];
    let prefill = parse_hex::<1>(&args.next().ok_or("missing prefill byte")?)?[0];
    if args.next().is_some() {
        return Err("unexpected extra argument".to_owned());
    }

    // These two writes are credited context outside the scoped native corridor.
    let mut output = [prefill; QC_ROW_RESULT_BYTES];
    output[..8].copy_from_slice(&0u64.to_le_bytes());
    output[0x60] = recovery;
    copy_prior_success_fields(&mut output, &raw20, &first, &second);

    let mut encoded = String::with_capacity(output.len() * 2);
    for byte in output {
        write!(&mut encoded, "{byte:02x}").map_err(|_| "hex format failure")?;
    }
    Ok(encoded)
}

fn main() {
    match run() {
        Ok(output) => println!("{output}"),
        Err(message) => {
            eprintln!("{message}");
            std::process::exit(2);
        }
    }
}
