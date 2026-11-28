//! Selected native action outcome entries for the replica Full response.

use std::io::{self, Write};

use crate::fixed_hex;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry<'a> {
    pub user: Option<[u8; 20]>,
    pub result: ActionResult<'a>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActionResult<'a> {
    Error(&'a str),
    Default,
    Token(u64),
    Spot(u64),
    ValidatorVote(bool),
}

fn quoted_text(out: &mut impl Write, value: &str) -> io::Result<()> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.write_all(b"\"")?;
    let bytes = value.as_bytes();
    let mut clean = 0;
    for (position, &byte) in bytes.iter().enumerate() {
        let mut wide = *b"\\u0000";
        let escaped: &[u8] = match byte {
            b'"' => b"\\\"",
            b'\\' => b"\\\\",
            b'\n' => b"\\n",
            b'\t' => b"\\t",
            b'\r' => b"\\r",
            0x08 => b"\\b",
            0x0c => b"\\f",
            0..=0x1f => {
                wide[4] = HEX[usize::from(byte >> 4)];
                wide[5] = HEX[usize::from(byte & 0xf)];
                &wide
            }
            _ => continue,
        };
        out.write_all(&bytes[clean..position])?;
        out.write_all(escaped)?;
        clean = position + 1;
    }
    out.write_all(&bytes[clean..])?;
    out.write_all(b"\"")
}

/// Emit the selected action result envelope accepted by the existing Full writer.
pub fn write_entry<W: Write>(out: &mut W, entry: &Entry<'_>) -> io::Result<()> {
    out.write_all(b"{\"user\":")?;
    match entry.user {
        Some(user) => fixed_hex(out, &user)?,
        None => out.write_all(b"null")?,
    }
    let status = if matches!(entry.result, ActionResult::Error(_)) {
        "err"
    } else {
        "ok"
    };
    write!(out, ",\"res\":{{\"status\":\"{status}\",\"response\":")?;
    match entry.result {
        ActionResult::Error(text) => quoted_text(out, text)?,
        ActionResult::Default => out.write_all(b"{\"type\":\"default\"}")?,
        ActionResult::Token(number) => write!(out, "{{\"type\":\"token\",\"data\":{number}}}")?,
        ActionResult::Spot(number) => write!(out, "{{\"type\":\"spot\",\"data\":{number}}}")?,
        ActionResult::ValidatorVote(vote) => {
            write!(out, "{{\"type\":\"validatorVote\",\"data\":{vote}}}")?
        }
    }
    out.write_all(b"}}")
}
