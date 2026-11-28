//! Selected replica response JSON emission. Entry serialization is an explicit boundary.
use std::io::{self, Write};

pub enum Response<'a, T> {
    Null,
    Hash(&'a [u8; 32]),
    Full(&'a [([u8; 32], Vec<T>)]),
}

fn hash<W: Write>(out: &mut W, bytes: &[u8; 32]) -> io::Result<()> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = [0u8; 68];
    encoded[..3].copy_from_slice(b"\"0x");
    for (i, b) in bytes.iter().enumerate() {
        encoded[3 + i * 2] = HEX[(b >> 4) as usize];
        encoded[4 + i * 2] = HEX[(b & 15) as usize];
    }
    encoded[67] = b'"';
    out.write_all(&encoded)
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
            hash(out, value)?;
            out.write_all(b"}")
        }
        Response::Full(rows) => {
            out.write_all(b"{\"Full\":[")?;
            for (i, (value, entries)) in rows.iter().enumerate() {
                if i != 0 {
                    out.write_all(b",")?;
                }
                out.write_all(b"[")?;
                hash(out, value)?;
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MissingPeriodicHash {
    pub post_height: u64,
}

/// Select the response for the observed replay worker's archive sink lane.
///
/// `mode` is the callback byte at offset +0x6b8 and `post_height` is the
/// returned height supplied to the same sink. Full rows and the optional
/// result fingerprint come from independently supplied fixture observations.
pub fn select_response<'a, T>(
    mode: u8,
    post_height: u64,
    rows: &'a [([u8; 32], Vec<T>)],
    periodic_hash: Option<&'a [u8; 32]>,
) -> Result<Response<'a, T>, MissingPeriodicHash> {
    if mode == 1 {
        return Ok(Response::Full(rows));
    }
    if post_height % 11 == 0 {
        return periodic_hash
            .map(Response::Hash)
            .ok_or(MissingPeriodicHash { post_height });
    }
    Ok(Response::Null)
}
