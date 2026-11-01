use node94_fixed_byte_readers::{read_20, read_32, Outcome};
use std::{env, fmt::Write as _, fs, io::{self, Write as _}};

fn bytes(text: &str) -> Result<Vec<u8>, String> {
    if text.len() % 2 != 0 || !text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err("canonical lowercase byte hex required".into());
    }
    (0..text.len()).step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i+2], 16).map_err(|e| e.to_string())).collect()
}

fn hex(raw: &[u8]) -> String {
    let mut text = String::with_capacity(raw.len()*2);
    for byte in raw { write!(&mut text, "{byte:02x}").unwrap(); }
    text
}

fn u64_hex(text: &str) -> Result<u64, String> {
    if text.len() != 16 { return Err("sixteen hex digits required".into()); }
    bytes(text)?;
    u64::from_str_radix(text, 16).map_err(|e| e.to_string())
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let path = args.next().ok_or("one raw stimulus path required")?;
    if args.next().is_some() { return Err("only one raw stimulus path allowed".into()); }
    let stimulus = fs::read_to_string(path).map_err(|e| e.to_string())?;
    let mut stdout = io::BufWriter::new(io::stdout().lock());
    for line in stimulus.lines() {
        let fields: Vec<_> = line.split('|').collect();
        if fields.len() != 8 { return Err("eight raw fields required".into()); }
        let id = fields[0];
        if id.is_empty() || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-') {
            return Err("ASCII raw identifier required".into());
        }
        let width: usize = fields[1].parse().map_err(|_| "invalid width")?;
        if width != 20 && width != 32 { return Err("width20 or32 required".into()); }
        if fields[2].is_empty() || !fields[2].bytes().all(|b| b.is_ascii_digit()) {
            return Err("decimal raw u32 mode required".into());
        }
        let mode: u32 = fields[2].parse().map_err(|_| "raw mode outsideu32")?;
        let limit = u64_hex(fields[3])?;
        let mut charged = u64_hex(fields[4])?;
        if fields[5].len() > 8192 { return Err("client wire limit4096bytes".into()); }
        let wire = bytes(fields[5])?;
        let mut output = bytes(fields[6])?;
        if output.len() != width+1 { return Err("complete initialized result required".into()); }
        let calls: usize = fields[7].parse().map_err(|_| "invalid call count")?;
        if !(1..=4).contains(&calls) { return Err("calls1..4 required".into()); }
        let mut input = wire.as_slice();
        for call in 1..=calls {
            let before = input.len();
            let outcome = match width {
                20 => read_20(&mut input, mode, limit, &mut charged,
                              output.as_mut_slice().try_into().unwrap()),
                32 => read_32(&mut input, mode, limit, &mut charged,
                              output.as_mut_slice().try_into().unwrap()),
                _ => unreachable!(),
            };
            let (kind, additional) = match outcome {
                Outcome::Value => ("value", String::from("null")),
                Outcome::End { additional } => ("end", additional.to_string()),
                Outcome::Charge => ("charge", String::from("null")),
            };
            writeln!(stdout, "{{\"additional\":{additional},\"call\":{call},\"charged\":{charged},\"consumed\":{},\"cursor\":{},\"id\":\"{id}\",\"kind\":\"{kind}\",\"limit\":{limit},\"mode\":{mode},\"output\":\"{}\",\"remaining\":{},\"tail\":\"{}\"}}",
                     before-input.len(), wire.len()-input.len(), hex(&output), input.len(), hex(input))
                .map_err(|e| e.to_string())?;
        }
    }
    stdout.flush().map_err(|e| e.to_string())
}

fn main() {
    if let Err(error) = run() { eprintln!("{error}"); std::process::exit(2); }
}
