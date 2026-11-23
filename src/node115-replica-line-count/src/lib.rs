//! Caller-visible output of the selected node #115 replica line-count operation.
use std::io;
use std::num::ParseIntError;
use std::process::{ExitStatus, Output};
use std::str::Utf8Error;

#[derive(Debug)]
pub enum CountError {
    Launch(io::Error),
    Status(ExitStatus),
    Encoding(Utf8Error),
    EmptyOutput,
    Count(ParseIntError),
}

/// Interpret an already-completed child result on the ordinary wc path.
/// The native adapter requires a successful status and validates all output
/// text before the line-count helper examines its first nonempty field.
pub fn line_count(result: io::Result<Output>) -> Result<u64, CountError> {
    let output = result.map_err(CountError::Launch)?;
    if !output.status.success() {
        return Err(CountError::Status(output.status));
    }
    let text = std::str::from_utf8(&output.stdout).map_err(CountError::Encoding)?;
    let first = text
        .split_whitespace()
        .next()
        .ok_or(CountError::EmptyOutput)?;
    first.parse().map_err(CountError::Count)
}
