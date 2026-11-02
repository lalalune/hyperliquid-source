//! Input-only client. No expected values, fixtures, oracle or filesystem reads.
use std::collections::HashSet;
use std::fmt::Write as FmtWrite;
use std::io::{self, Read, Write};
use std::str::FromStr;
use visor_readiness_value::{Timestamp, is_strictly_past_deadline};

fn number<T: FromStr>(text: &str, signed: bool) -> Result<T, String> {
    let digits = if signed {
        text.strip_prefix('-').unwrap_or(text)
    } else {
        text
    };
    if digits.is_empty()
        || !digits.bytes().all(|b| b.is_ascii_digit())
        || (digits.len() > 1 && digits.starts_with('0'))
        || text == "-0"
    {
        return Err("noncanonical decimal".into());
    }
    text.parse().map_err(|_| "integer type range".into())
}

fn parts(fields: &[&str]) -> Result<Option<Timestamp>, String> {
    if fields.len() != 4 {
        return Err("timestamp field count".into());
    }
    Ok(Timestamp::from_parts(
        number(fields[0], true)?,
        number(fields[1], false)?,
        number(fields[2], false)?,
        number(fields[3], false)?,
    ))
}

fn value_line(output: &mut String, id: &str, value: Option<Timestamp>) {
    match value {
        Some(value) => {
            let (date, second, nano) = value.raw_words();
            writeln!(output, "{id}\tOK\t{date}\t{second}\t{nano}").unwrap();
        }
        None => writeln!(output, "{id}\tDOMAIN").unwrap(),
    }
}

fn run() -> Result<(), String> {
    if std::env::args().len() != 1 {
        return Err("client accepts no arguments".into());
    }
    let mut input = String::new();
    io::stdin()
        .read_to_string(&mut input)
        .map_err(|e| e.to_string())?;
    let mut output = String::new();
    let mut ids = HashSet::new();
    for line in input.split_inclusive('\n') {
        let line = line.strip_suffix('\n').ok_or("missing LF")?;
        let fields: Vec<_> = line.split('\t').collect();
        let id = fields.first().copied().ok_or("missing ID")?;
        if id.len() != 8
            || !id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || !ids.insert(id)
        {
            return Err("invalid or duplicate opaque ID".into());
        }
        match fields.get(1).copied() {
            Some("P") if fields.len() == 6 => value_line(&mut output, id, parts(&fields[2..])?),
            Some("C") if fields.len() == 4 => value_line(
                &mut output,
                id,
                Timestamp::from_clock_sample(number(fields[2], true)?, number(fields[3], false)?),
            ),
            Some("D") if fields.len() == 6 => {
                value_line(
                    &mut output,
                    id,
                    parts(&fields[2..])?.map(Timestamp::deadline_60),
                );
            }
            Some("R") if fields.len() == 10 => {
                let source = parts(&fields[2..6])?;
                let current = parts(&fields[6..10])?;
                match (source, current) {
                    (Some(source), Some(current)) => {
                        let result = u8::from(is_strictly_past_deadline(current, source));
                        writeln!(output, "{id}\tBOOL\t{result}").unwrap();
                    }
                    _ => writeln!(output, "{id}\tDOMAIN").unwrap(),
                }
            }
            _ => return Err("operation or field count".into()),
        }
    }
    // Buffer all values until every row is valid: malformed later rows cannot
    // leak a successful prefix. String writes above cannot fail.
    io::stdout()
        .write_all(output.as_bytes())
        .map_err(|e| e.to_string())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("invalid input: {error}");
        std::process::exit(2);
    }
}
