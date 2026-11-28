//! Query the public string-width API without a terminal or a captured executable.
use std::error::Error;
use std::io::{self, BufRead, Write};
use unicode_width::UnicodeWidthStr;

fn widths(text: &str) -> [u8; 2] {
    [
        text.width().try_into().unwrap(),
        text.width_cjk().try_into().unwrap(),
    ]
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut out = io::BufWriter::new(io::stdout().lock());
    if std::env::args().nth(1).as_deref() == Some("--sequences") {
        for line in io::stdin().lock().lines() {
            let mut text = String::new();
            for cp in line?.split_whitespace() {
                text.push(char::from_u32(u32::from_str_radix(cp, 16)?).ok_or("invalid scalar")?);
            }
            out.write_all(&widths(&text))?;
        }
    } else {
        let mut text = String::with_capacity(8);
        for c in (0..=0x10ffff).filter_map(char::from_u32) {
            text.clear();
            text.push(c);
            out.write_all(&widths(&text))?;
            let size = text.len();
            for selector in ['\u{fe0e}', '\u{fe0f}'] {
                text.truncate(size);
                text.push(selector);
                out.write_all(&widths(&text))?;
            }
        }
    }
    out.flush()?;
    Ok(())
}
