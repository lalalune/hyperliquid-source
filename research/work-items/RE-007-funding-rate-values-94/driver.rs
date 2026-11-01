//! Newly authored MIT input-only client for the frozen TSV protocol.
//! It reads no expected outputs, semantic labels, oracle or fixture paths.

use node94_funding_rate_values::{funding_rate_bits, insertion_bits};
use std::collections::BTreeSet;
use std::fmt::Write as FmtWrite;
use std::io::{Read, Write};

fn word(text: &str) -> Result<u64, &'static str> {
    if text.len() != 16
        || !text
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err("noncanonical hexadecimal word");
    }
    u64::from_str_radix(text, 16).map_err(|_| "hexadecimal word overflow")
}

fn optional(text: &str) -> Result<Option<u64>, &'static str> {
    if text == "-" {
        Ok(None)
    } else {
        word(text).map(Some)
    }
}

fn process(input: &str) -> Result<String, &'static str> {
    if !input.is_ascii() || (!input.is_empty() && !input.ends_with('\n')) {
        return Err("ASCII and final LF required");
    }
    let mut seen = BTreeSet::new();
    let mut output = String::new();
    for line in input.split_terminator('\n') {
        let fields: Vec<_> = line.split('\t').collect();
        if fields.len() < 5 {
            return Err("truncated record");
        }
        let id = word(fields[0])?;
        if !seen.insert(id) {
            return Err("duplicate ID");
        }
        let interest = optional(fields[1])?;
        let multiplier = optional(fields[2])?;
        let clamp = word(fields[3])?;
        let samples = if fields[4] == "-" {
            if fields.len() != 5 {
                return Err("missing sample record has trailing fields");
            }
            None
        } else {
            let count_text = fields[4];
            if count_text.is_empty()
                || !count_text.bytes().all(|c| c.is_ascii_digit())
                || (count_text.len() > 1 && count_text.starts_with('0'))
            {
                return Err("noncanonical count");
            }
            let count: usize = count_text.parse().map_err(|_| "count overflow")?;
            if count > isize::MAX as usize / 8 || fields.len() - 5 != count {
                return Err("count does not match admitted fields");
            }
            let values = fields[5..]
                .iter()
                .map(|s| word(s))
                .collect::<Result<Vec<_>, _>>()?;
            Some(values)
        };
        let rate = funding_rate_bits(samples.as_deref(), interest, multiplier, clamp);
        let active = rate.map_or_else(|| "-".to_owned(), |bits| format!("{bits:016x}"));
        writeln!(
            &mut output,
            "{id:016x}\t{active}\t{:016x}",
            insertion_bits(rate)
        )
        .map_err(|_| "output formatting")?;
    }
    Ok(output)
}

fn main() {
    let result = (|| {
        if std::env::args_os().len() != 1 {
            return Err("no arguments accepted");
        }
        let mut input = String::new();
        std::io::stdin()
            .read_to_string(&mut input)
            .map_err(|_| "input read")?;
        let output = process(&input)?;
        std::io::stdout()
            .write_all(output.as_bytes())
            .map_err(|_| "output write")
    })();
    if let Err(message) = result {
        eprintln!("{message}");
        std::process::exit(2);
    }
}
