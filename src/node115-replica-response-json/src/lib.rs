//! Selected replica response JSON emission.
pub mod entry;
use std::io::{self, Write};

pub enum Response<'a, T> {
    Null,
    Hash(&'a [u8; 32]),
    Full(&'a [([u8; 32], Vec<T>)]),
}

fn fixed_hex<W: Write>(out: &mut W, bytes: &[u8]) -> io::Result<()> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = [0u8; 68];
    encoded[..3].copy_from_slice(b"\"0x");
    for (i, b) in bytes.iter().enumerate() {
        encoded[3 + i * 2] = HEX[(b >> 4) as usize];
        encoded[4 + i * 2] = HEX[(b & 15) as usize];
    }
    let closing_quote = 3 + bytes.len() * 2;
    encoded[closing_quote] = b'"';
    out.write_all(&encoded[..=closing_quote])
}

/// Emit the selected response branch, preserving the order of rows and entries.
/// `write_entry` is the separate native entry-writer boundary; its error stops
/// immediately, leaving the already written prefix in the supplied output.
/// I/O errors are host errors, not a reconstruction of native allocation ABI.
pub fn write_response<W: Write, T>(
    out: &mut W,
    response: Response<'_, T>,
    mut write_entry: impl FnMut(&mut W, &T) -> io::Result<()>,
) -> io::Result<()> {
    match response {
        Response::Null => out.write_all(b"null"),
        Response::Hash(value) => {
            out.write_all(b"{\"Hash\":")?;
            fixed_hex(out, value)?;
            out.write_all(b"}")
        }
        Response::Full(rows) => {
            out.write_all(b"{\"Full\":[")?;
            for (i, (value, entries)) in rows.iter().enumerate() {
                if i != 0 {
                    out.write_all(b",")?;
                }
                out.write_all(b"[")?;
                fixed_hex(out, value)?;
                out.write_all(b",[")?;
                for (j, entry) in entries.iter().enumerate() {
                    if j != 0 {
                        out.write_all(b",")?;
                    }
                    write_entry(out, entry)?;
                }
                out.write_all(b"]]")?;
            }
            out.write_all(b"]}")
        }
    }
}
