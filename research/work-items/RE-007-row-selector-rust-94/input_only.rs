//! Uncompiled input-only driver for a conditional posthash value comparison.
//! No expected results, names, golden-file paths, native pointers or Once calls.
#![forbid(unsafe_code)]

use node94_margin_risk::row_selector::{select_row_after_hash, RowChoice, SelectorInputError};
use std::io::{self, Read, Write};

struct Reader<'a> {
    raw: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N], &'static str> {
        let end = self.at.checked_add(N).ok_or("offset overflow")?;
        let span = self.raw.get(self.at..end).ok_or("truncated input")?;
        self.at = end;
        span.try_into().map_err(|_| "field width")
    }

    fn u32(&mut self) -> Result<u32, &'static str> {
        Ok(u32::from_le_bytes(self.take()?))
    }

    fn u64(&mut self) -> Result<u64, &'static str> {
        Ok(u64::from_le_bytes(self.take()?))
    }
}

fn run(raw: &[u8]) -> Result<Vec<u8>, &'static str> {
    let mut r = Reader { raw, at: 0 };
    if &r.take::<8>()? != b"R94SIN01" {
        return Err("wrong input magic");
    }
    let count = r.u32()?;
    if count > 4096 {
        return Err("driver case bound");
    }
    let mut output = Vec::new();
    output.extend_from_slice(b"R94SOUT1");
    output.extend_from_slice(&count.to_le_bytes());
    for _ in 0..count {
        let id = r.u32()?;
        let entry_count = r.u64()?;
        let hash = r.u64()?;
        let late_state = r.u32()?;
        let capacity = usize::try_from(r.u32()?).map_err(|_| "capacity width")?;
        let key_count = usize::try_from(r.u32()?).map_err(|_| "key-count width")?;
        let query = r.take::<20>()?;
        if capacity > 256 || key_count > 256 {
            return Err("driver allocation bound");
        }
        let mut controls = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            controls.push(r.take::<1>()?[0]);
        }
        let mut keys = Vec::with_capacity(key_count);
        for _ in 0..key_count {
            keys.push(r.take::<20>()?);
        }
        let selected = select_row_after_hash(entry_count, hash, &controls, &keys, &query, late_state);
        let (kind, predicate, index) = match selected {
            Ok(selected) => {
                let (kind, index) = match selected.choice {
                    RowChoice::SharedDefault => (0u8, u64::MAX),
                    RowChoice::Bucket(index) => (1u8, index as u64),
                };
                (kind, u8::from(selected.initializer_needed), index)
            }
            Err(error) => (2u8, 0u8, match error {
                SelectorInputError::ControlShape => 0u64,
                SelectorInputError::KeyCoverage => 1u64,
                SelectorInputError::NoNormalExit => 2u64,
            }),
        };
        output.extend_from_slice(&id.to_le_bytes());
        output.extend_from_slice(&[kind, predicate]);
        output.extend_from_slice(&index.to_le_bytes());
    }
    if r.at != raw.len() {
        return Err("trailing input");
    }
    Ok(output)
}

fn main() {
    let mut input = Vec::new();
    let result = io::stdin()
        .read_to_end(&mut input)
        .map_err(|_| "stdin read failed")
        .and_then(|_| run(&input));
    match result {
        Ok(output) => {
            if let Err(error) = io::stdout().write_all(&output) {
                eprintln!("stdout write failed: {error}");
                std::process::exit(2);
            }
        }
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(2);
        }
    }
}
