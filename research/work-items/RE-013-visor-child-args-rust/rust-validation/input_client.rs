//! Input-only client: no oracle, expected-file, source-fixture or filesystem reads.
use std::fmt::Write as _;
use std::io::{self, BufWriter, Read, Write};
use visor_child_args::{CollectError, collect_child_args, native_descriptor_bytes};

fn parse_bytes(text: &str) -> Result<Vec<u8>, String> {
    if text == "-" {
        return Ok(Vec::new());
    }
    if text.is_empty()
        || !text.len().is_multiple_of(2)
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("noncanonical byte hex".into());
    }
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).map_err(|_| "hex text")?;
            u8::from_str_radix(text, 16).map_err(|_| "hex byte".into())
        })
        .collect()
}

fn serialize(values: &[String]) -> String {
    if values.is_empty() {
        return ".".into();
    }
    let mut out = String::new();
    for (index, value) in values.iter().enumerate() {
        if index != 0 {
            out.push(',');
        }
        if value.is_empty() {
            out.push('-');
        } else {
            for byte in value.bytes() {
                write!(out, "{byte:02x}").expect("String formatting");
            }
        }
    }
    out
}

fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let lengths = match args.as_slice() {
        [] => false,
        [mode] if mode == "lengths" => true,
        _ => return Err("client accepts only optional lengths mode".into()),
    };
    let mut input = String::new();
    io::stdin()
        .read_to_string(&mut input)
        .map_err(|e| e.to_string())?;
    let mut writer = BufWriter::new(io::stdout().lock());
    for (index, line) in input.split_inclusive('\n').enumerate() {
        let line = line.strip_suffix('\n').ok_or("missing LF")?;
        let fields: Vec<_> = line.split('\t').collect();
        let id = if lengths {
            format!("n{index:03}")
        } else {
            format!("c{index:06}")
        };
        if fields.len() != 2 || fields[0] != id {
            return Err("input fields or ordered opaque ID".into());
        }
        let result = if lengths {
            let count: u64 = fields[1].parse().map_err(|_| "u64 count")?;
            if count.to_string() != fields[1] {
                return Err("noncanonical count".into());
            }
            match native_descriptor_bytes(count) {
                Some(bytes) => format!("OK\t{bytes}"),
                None => "DOMAIN".into(),
            }
        } else {
            let owned: Vec<Option<Vec<u8>>> = if fields[1] == "." {
                Vec::new()
            } else {
                fields[1]
                    .split(',')
                    .map(|item| {
                        if item == "~" {
                            Ok(None)
                        } else {
                            parse_bytes(item).map(Some)
                        }
                    })
                    .collect::<Result<_, String>>()?
            };
            let borrowed: Vec<Option<&[u8]>> = owned.iter().map(|item| item.as_deref()).collect();
            match collect_child_args(&borrowed) {
                Ok(values) => format!("OK\t{}", serialize(&values)),
                Err(CollectError::InvalidUtf8 { argument_index }) => {
                    format!("INVALID\t{argument_index}")
                }
                Err(CollectError::DescriptorCountOutsideDomain) => "DOMAIN".into(),
                Err(CollectError::AllocationFailure) => "ALLOCATION".into(),
            }
        };
        writeln!(writer, "{id}\t{result}").map_err(|e| e.to_string())?;
    }
    writer.flush().map_err(|e| e.to_string())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("invalid fixture: {error}");
        std::process::exit(2);
    }
}
