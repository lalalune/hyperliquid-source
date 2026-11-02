//! Input-only qualification client. It never opens a fixture or expected file.
use node94_tc_abort_projection::{fold, merge, plan, BridgeInput, Observation};
use std::fmt::Write;
use std::io::{self, BufRead};

fn hex(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(2 * bytes.len());
    for byte in bytes {
        write!(text, "{byte:02x}").unwrap();
    }
    text
}

fn bytes<const N: usize>(word: Option<&str>) -> Result<[u8; N], ()> {
    let s = word.ok_or(())?;
    if s.len() != N * 2 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(());
    }
    let mut out = [0; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| ())?;
    }
    Ok(out)
}

fn number(word: Option<&str>) -> Result<u64, ()> {
    let s = word.ok_or(())?;
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(());
    }
    s.parse().map_err(|_| ())
}

fn byte(word: Option<&str>) -> Result<u8, ()> {
    u8::try_from(number(word)?).map_err(|_| ())
}

fn run(line: &str) -> Result<String, ()> {
    let mut words = line.split_whitespace();
    let result = match words.next().ok_or(())? {
        "P" => {
            let values = plan(BridgeInput {
                logical_len: number(words.next())?,
                producer_len: number(words.next())?,
                minimum: number(words.next())?,
                splits: number(words.next())?,
                migrated: byte(words.next())?,
                observed_cancel: byte(words.next())?,
                observed_threads: number(words.next())?,
            });
            format!(
                "P {} {} {} {} {} {}",
                values[0], values[1], values[2], values[3], values[4], values[5]
            )
        }
        "M" => {
            let out = merge(
                bytes(words.next())?,
                bytes(words.next())?,
                bytes(words.next())?,
            );
            format!(
                "M {} {} {}",
                hex(&out.output),
                out.written_bytes,
                out.dropped.map_or_else(|| "-".to_owned(), |x| hex(&x))
            )
        }
        "F" => {
            let folder = bytes(words.next())?;
            let flag = byte(words.next())?;
            let count = usize::try_from(number(words.next())?).map_err(|_| ())?;
            if count > 100000 {
                return Err(());
            } // client resource policy only
            let mut items = Vec::with_capacity(count);
            for _ in 0..count {
                items.push(Observation {
                    result: bytes(words.next())?,
                    flag_after_call: byte(words.next())?,
                });
            }
            let out = fold(folder, flag, &items);
            format!(
                "F {} {} {} {} {} {} {}",
                hex(&out.folder),
                out.flag,
                out.calls,
                out.flag_reads,
                out.flag_writes,
                out.stop,
                out.dropped.map_or_else(|| "-".to_owned(), |x| hex(&x))
            )
        }
        _ => return Err(()),
    };
    if words.next().is_some() {
        return Err(());
    }
    Ok(result)
}

fn main() {
    if std::env::args_os().len() != 1 {
        std::process::exit(2);
    }
    for line in io::stdin().lock().lines() {
        let result = line.map_err(|_| ()).and_then(|line| run(&line));
        match result {
            Ok(out) => println!("{out}"),
            Err(()) => {
                eprintln!("invalid input");
                std::process::exit(2);
            }
        }
    }
}
