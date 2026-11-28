//! Compact JSON for the ordinary typed TWAP outcomes.

use std::io::{self, Write};

use crate::entry::quoted_text;

fn error_status(out: &mut impl Write, message: &str) -> io::Result<()> {
    out.write_all(b"{\"error\":")?;
    quoted_text(out, message)?;
    out.write_all(b"}")
}

pub fn write_created(out: &mut impl Write, result: Result<u64, &str>) -> io::Result<()> {
    out.write_all(b"{\"type\":\"twapOrder\",\"data\":{\"status\":")?;
    match result {
        Ok(id) => write!(out, "{{\"running\":{{\"twapId\":{id}}}}}")?,
        Err(message) => error_status(out, message)?,
    }
    out.write_all(b"}}")
}

pub fn write_cancelled(out: &mut impl Write, result: Result<(), &str>) -> io::Result<()> {
    out.write_all(b"{\"type\":\"twapCancel\",\"data\":{\"status\":")?;
    match result {
        Ok(()) => out.write_all(b"\"success\"")?,
        Err(message) => error_status(out, message)?,
    }
    out.write_all(b"}}")
}
