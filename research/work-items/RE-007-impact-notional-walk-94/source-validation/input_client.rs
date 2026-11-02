//! Input-only client for the real linked component; no oracle/answer/file reads.
use node94_funding_premium_values::{Book, Entry, Input, Refusal, Slot, evaluate};
use std::collections::HashSet;
use std::fmt::Write as FmtWrite;
use std::io::{self, Read, Write};

fn word(text: &str) -> Result<u64, String> {
    if text.len() != 16
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("expected sixteen lowercase hex digits".into());
    }
    u64::from_str_radix(text, 16).map_err(|_| "word range".into())
}

fn entries(words: &[u64], cursor: &mut usize, count: usize) -> Result<Vec<Entry>, String> {
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        values.push(Entry {
            key: words[*cursor] as i64,
            active: u8::try_from(words[*cursor + 1]).map_err(|_| "active byte range")?,
            head: words[*cursor + 2],
        });
        *cursor += 3;
    }
    Ok(values)
}

fn run() -> Result<(), String> {
    if std::env::args().len() != 1 {
        return Err("client accepts no arguments".into());
    }
    let mut input = String::new();
    io::stdin()
        .read_to_string(&mut input)
        .map_err(|e| e.to_string())?;
    let mut ids = HashSet::new();
    let mut output = String::new();
    for line in input.split_inclusive('\n') {
        let line = line.strip_suffix('\n').ok_or("missing LF")?;
        let words = line.split(' ').map(word).collect::<Result<Vec<_>, _>>()?;
        if words.len() < 10 {
            return Err("missing fixed fields".into());
        }
        let id = words[0];
        if !ids.insert(id) {
            return Err("duplicate opaque ID".into());
        }
        let scale = u8::try_from(words[4]).map_err(|_| "scale byte range")?;
        let mode = u8::try_from(words[5]).map_err(|_| "mode byte range")?;
        let member = match words[6] {
            0 => false,
            1 => true,
            _ => return Err("membership boolean range".into()),
        };
        let n1 = usize::try_from(words[7]).map_err(|_| "first count range")?;
        let n2 = usize::try_from(words[8]).map_err(|_| "second count range")?;
        let ns = usize::try_from(words[9]).map_err(|_| "slot count range")?;
        let needed = n1
            .checked_add(n2)
            .and_then(|n| n.checked_mul(3))
            .and_then(|n| ns.checked_mul(4).and_then(|s| n.checked_add(s)))
            .and_then(|n| n.checked_add(10))
            .ok_or("count arithmetic overflow")?;
        if needed != words.len() {
            return Err("word count mismatch".into());
        }
        let mut cursor = 10;
        let first = entries(&words, &mut cursor, n1)?;
        let second = entries(&words, &mut cursor, n2)?;
        let mut slots = Vec::with_capacity(ns);
        for _ in 0..ns {
            slots.push(Slot {
                tag: u32::try_from(words[cursor]).map_err(|_| "slot tag range")?,
                quantity: words[cursor + 1],
                continuation: words[cursor + 2],
                next: words[cursor + 3],
            });
            cursor += 4;
        }
        let result = evaluate(Input {
            asset: words[1],
            oracle: words[2],
            target: words[3],
            scale,
            mode,
            divide_by_100: member,
            book: Book {
                first: &first,
                second: &second,
                slots: &slots,
            },
        });
        match result {
            Ok(value) => {
                let record = value.record;
                if let Some(premium) = value.premium {
                    writeln!(
                        output,
                        "{id:016x} V {:016x} {:016x} {:016x} {:016x} {:016x} {:016x}",
                        premium.bits,
                        premium.first_impact,
                        premium.second_impact,
                        record.asset,
                        record.tag,
                        record.payload
                    )
                    .unwrap();
                } else {
                    writeln!(
                        output,
                        "{id:016x} N {:016x} {:016x} {:016x}",
                        record.asset, record.tag, record.payload
                    )
                    .unwrap();
                }
            }
            Err(reason) => {
                let label = match reason {
                    Refusal::InvalidScale => "SCALE",
                    Refusal::ZeroTarget => "TARGET",
                    Refusal::CycleFirst => "CYCLE1",
                    Refusal::CycleSecond => "CYCLE2",
                };
                writeln!(output, "{id:016x} E {label}").unwrap();
            }
        }
    }
    // A malformed suffix must not publish a successful prefix.
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
