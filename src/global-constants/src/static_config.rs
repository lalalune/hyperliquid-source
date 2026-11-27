//! Node #115 `global_constants/src/static_config.rs` reconstruction.
//!
//! Target coordinates:
//! - `0x64f06c0` (`STATIC_CONFIG` `LazyLock<StaticConfig>`, layout:
//!   `+0x00 home_dir`, `+0x18 cham_dir`, `+0x30 code_dir`, `+0x48 aws_name`)
//! - `0x17785f0` (`StaticConfig::new`, panics at `static_config.rs:24:9`:
//!   `"cham_dir does not exist: {cham_dir}"`)
//! - `0x17780c0` (`resolve_cham_dir`, checks `/cham`, then `/hl`, else
//!   `create_dir_all` panicking via `0x1778270` at `static_config.rs:61:17`:
//!   `"could not create {hl_dir}: {err}"`)
//! - `0x17782e0` (`home_dir`)
//! - `0x17783e0` (`read_aws_name`, reads `{code_dir}/static_config`, falls back
//!   to `AwsName::NvTestnet` (33) on read or JSON parse error)
//! - `0x1775dd0` -> `0x17771b0` -> `0x1773070` -> `0x1777080` (`StaticConfig`
//!   JSON deserializer with missing-`aws_name` fallback `0x1773fd0`)
//! - `0x1772fa0` (`aws_name_path`, formats `{cham_dir}/aws_name`)

use std::env;
use std::fmt;
use std::fs;
use std::path::Path;
use std::str::FromStr;
use std::sync::LazyLock;

use crate::aws_name::AwsName;

/// JSON whitespace bitmask observed in `0x1773098`, `0x1775dd0`, and `0x1777080`:
/// bits 9 (`\t`), 10 (`\n`), 13 (`\r`), and 32 (`' '`).
/// Notably excludes `\x0b`, `\x0c`, and non-ASCII whitespace such as U+00A0.
pub const JSON_WHITESPACE_MASK: u64 = 0x1_0000_2600;

/// Global lazily initialized static configuration cell (`0x64f06c0` in node #115).
pub static STATIC_CONFIG: LazyLock<StaticConfig> = LazyLock::new(StaticConfig::load);

/// Static node configuration matching the 0x49-byte payload layout at `0x17785f0`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StaticConfig {
    pub home_dir: String,
    pub cham_dir: String,
    pub code_dir: String,
    pub aws_name: AwsName,
}

impl StaticConfig {
    /// Initialize from the process environment's home directory (`0x17785f0`).
    pub fn load() -> Self {
        Self::load_from_home(home_dir())
    }

    /// Initialize from an explicit `home_dir` without touching the caller's
    /// real `$HOME` (exact control flow of `0x17785f0`).
    pub fn load_from_home(home_dir: impl Into<String>) -> Self {
        let home_dir = home_dir.into();
        let cham_dir = resolve_cham_dir(&home_dir);
        if !Path::new(&cham_dir).is_dir() {
            panic!("cham_dir does not exist: {cham_dir}");
        }
        let code_dir = code_dir_for_cham_dir(&cham_dir);
        let aws_name = read_aws_name(&code_dir, &cham_dir);
        Self {
            home_dir,
            cham_dir,
            code_dir,
            aws_name,
        }
    }
}

/// Resolve the user's home directory (`0x17782e0` -> Rust 1.95.0 stdlib `0x5c9abb0`,
/// 253/253 B relocation-qualified compiled-byte match).
///
/// Calls `std::env::home_dir()`, which checks `HOME` and on Unix falls back to
/// `sysconf(_SC_GETPW_R_SIZE_MAX)` + `getpwuid_r` when `HOME` is unset or empty,
/// returning `String::new()` if absent or non-UTF-8 (exact behavior of `0x17782e0`).
pub fn home_dir() -> String {
    fn inner() -> Option<String> {
        #[allow(deprecated)]
        let p = env::home_dir()?;
        Some(p.to_str()?.to_string())
    }
    inner().unwrap_or_default()
}

/// Select `{home_dir}/cham` if it is a directory, otherwise `{home_dir}/hl`,
/// creating `{home_dir}/hl` recursively if needed (`0x17780c0` + `0x1778270`).
pub fn resolve_cham_dir(home_dir: &str) -> String {
    let cham = format!("{home_dir}/cham");
    if Path::new(&cham).is_dir() {
        return cham;
    }
    let hl = format!("{home_dir}/hl");
    if !Path::new(&hl).is_dir() {
        if let Err(err) = fs::create_dir_all(&hl) {
            panic!("could not create {hl}: {err}");
        }
    }
    hl
}

/// Format `{cham_dir}/code` (suffix template `0x43de2f` in `0x17785f0`).
pub fn code_dir_for_cham_dir(cham_dir: &str) -> String {
    format!("{cham_dir}/code")
}

/// Format `{cham_dir}/aws_name` (suffix template `0x44205d` in `0x1772fa0`).
pub fn aws_name_path_for_cham_dir(cham_dir: &str) -> String {
    format!("{cham_dir}/aws_name")
}

/// Format `{code_dir}/static_config` (suffix template `0x4401ef` in `0x17783e0`).
pub fn static_config_file_path(code_dir: &str) -> String {
    format!("{code_dir}/static_config")
}

/// Read `{code_dir}/static_config` and extract `AwsName` (`0x17783e0`).
///
/// - File read failure -> returns `AwsName::NvTestnet` (discriminant 33).
/// - JSON parse failure (including trailing bytes, duplicate `aws_name`,
///   invalid syntax, or unknown `AwsName` variant) -> returns `AwsName::NvTestnet`.
/// - Well-formed JSON object without `"aws_name"`, or empty JSON array `[]` ->
///   consults `{cham_dir}/aws_name` via [`AwsName::read_from_file`] (`0x1773fd0`),
///   which panics if that fallback file is missing or contains an unknown name.
pub fn read_aws_name(code_dir: &str, cham_dir: &str) -> AwsName {
    let path = static_config_file_path(code_dir);
    let Ok(contents) = fs::read_to_string(&path) else {
        return AwsName::DEFAULT_FALLBACK;
    };
    let fallback_path = aws_name_path_for_cham_dir(cham_dir);
    match parse_static_config_json(&contents, || AwsName::read_from_file(Path::new(&fallback_path)))
    {
        Ok(name) => name,
        Err(_) => AwsName::DEFAULT_FALLBACK,
    }
}

/// Error classes produced by the `StaticConfig` JSON parser (`0x1775dd0`/`0x17771b0`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StaticConfigParseError {
    Eof,
    ExpectedStructObjectOrSeq,
    ExpectedString,
    ExpectedColon,
    ExpectedCommaOrClose,
    DuplicateField,
    UnknownVariant,
    InvalidUnitVariant,
    InvalidJsonValue,
    TrailingCharacters,
}

impl fmt::Display for StaticConfigParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Eof => f.write_str("unexpected end of JSON input"),
            Self::ExpectedStructObjectOrSeq => f.write_str("expected struct StaticConfig"),
            Self::ExpectedString => f.write_str("expected JSON string"),
            Self::ExpectedColon => f.write_str("expected `:`"),
            Self::ExpectedCommaOrClose => f.write_str("expected `,` or closing delimiter"),
            Self::DuplicateField => f.write_str("duplicate field `aws_name`"),
            Self::UnknownVariant => f.write_str("unknown AwsName variant"),
            Self::InvalidUnitVariant => f.write_str("invalid externally-tagged unit variant"),
            Self::InvalidJsonValue => f.write_str("invalid JSON value"),
            Self::TrailingCharacters => f.write_str("trailing characters after JSON document"),
        }
    }
}

impl std::error::Error for StaticConfigParseError {}

/// Test whether `b` is accepted by the node #115 whitespace mask `0x100002600`.
#[inline]
pub const fn is_json_whitespace(b: u8) -> bool {
    b <= 32 && ((JSON_WHITESPACE_MASK >> b) & 1) != 0
}

/// Parse a `StaticConfig` JSON document (`0x1775dd0` -> `0x17771b0` -> `0x1773070`).
///
/// Mirrors the serde_json deserializer observed in node #115:
/// - Accepts `{ ... }` (ignoring unknown fields, rejecting duplicate `"aws_name"`)
///   and `[ ... ]` (0-element or 1-element tuple form).
/// - Accepts `"aws_name"` values as either a JSON string `"NvTestnet"` or an
///   externally-tagged unit variant object `{"NvTestnet": null}`.
/// - Invokes `missing_name_fallback` when a well-formed object omits `"aws_name"`
///   or an array is empty `[]`.
/// - Enforces trailing-whitespace-only end check using [`JSON_WHITESPACE_MASK`].
pub fn parse_static_config_json(
    input: &str,
    missing_name_fallback: impl FnOnce() -> AwsName,
) -> Result<AwsName, StaticConfigParseError> {
    let mut parser = JsonParser::new(input.as_bytes());
    parser.skip_ws();
    let Some(first) = parser.peek() else {
        return Err(StaticConfigParseError::Eof);
    };

    let parsed = match first {
        b'{' => parser.parse_object(missing_name_fallback)?,
        b'[' => parser.parse_seq(missing_name_fallback)?,
        _ => return Err(StaticConfigParseError::ExpectedStructObjectOrSeq),
    };

    parser.skip_ws();
    if parser.pos != parser.bytes.len() {
        return Err(StaticConfigParseError::TrailingCharacters);
    }
    Ok(parsed)
}

struct JsonParser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> JsonParser<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let b = self.peek()?;
        self.pos += 1;
        Some(b)
    }

    fn skip_ws(&mut self) {
        while let Some(b) = self.peek() {
            if is_json_whitespace(b) {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn parse_object(
        &mut self,
        missing_name_fallback: impl FnOnce() -> AwsName,
    ) -> Result<AwsName, StaticConfigParseError> {
        self.pos += 1; // '{'
        self.skip_ws();
        let mut found: Option<AwsName> = None;

        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(missing_name_fallback());
        }

        loop {
            self.skip_ws();
            let key = self.parse_string()?;
            self.skip_ws();
            if self.bump() != Some(b':') {
                return Err(StaticConfigParseError::ExpectedColon);
            }
            self.skip_ws();
            if key == "aws_name" {
                if found.is_some() {
                    return Err(StaticConfigParseError::DuplicateField);
                }
                found = Some(self.parse_aws_name_value()?);
            } else {
                self.skip_value()?;
            }
            self.skip_ws();
            match self.bump() {
                Some(b',') => continue,
                Some(b'}') => break,
                _ => return Err(StaticConfigParseError::ExpectedCommaOrClose),
            }
        }

        Ok(match found {
            Some(name) => name,
            None => missing_name_fallback(),
        })
    }

    fn parse_seq(
        &mut self,
        missing_name_fallback: impl FnOnce() -> AwsName,
    ) -> Result<AwsName, StaticConfigParseError> {
        self.pos += 1; // '['
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(missing_name_fallback());
        }
        let name = self.parse_aws_name_value()?;
        self.skip_ws();
        if self.bump() != Some(b']') {
            return Err(StaticConfigParseError::ExpectedCommaOrClose);
        }
        Ok(name)
    }

    /// Matches `0x1773070` (`AwsName` serde deserializer): accepts `"Variant"`
    /// or `{"Variant": null}`.
    fn parse_aws_name_value(&mut self) -> Result<AwsName, StaticConfigParseError> {
        self.skip_ws();
        match self.peek() {
            Some(b'"') => {
                let s = self.parse_string()?;
                AwsName::from_str(&s).map_err(|_| StaticConfigParseError::UnknownVariant)
            }
            Some(b'{') => {
                self.pos += 1;
                self.skip_ws();
                let s = self.parse_string()?;
                let variant =
                    AwsName::from_str(&s).map_err(|_| StaticConfigParseError::UnknownVariant)?;
                self.skip_ws();
                if self.bump() != Some(b':') {
                    return Err(StaticConfigParseError::ExpectedColon);
                }
                self.skip_ws();
                if !self.consume_literal(b"null") {
                    return Err(StaticConfigParseError::InvalidUnitVariant);
                }
                self.skip_ws();
                if self.bump() != Some(b'}') {
                    return Err(StaticConfigParseError::InvalidUnitVariant);
                }
                Ok(variant)
            }
            None => Err(StaticConfigParseError::Eof),
            Some(_) => Err(StaticConfigParseError::ExpectedString),
        }
    }

    fn parse_string(&mut self) -> Result<String, StaticConfigParseError> {
        if self.bump() != Some(b'"') {
            return Err(StaticConfigParseError::ExpectedString);
        }
        let mut out = String::new();
        while let Some(b) = self.bump() {
            match b {
                b'"' => return Ok(out),
                b'\\' => {
                    let esc = self.bump().ok_or(StaticConfigParseError::Eof)?;
                    match esc {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{0008}'),
                        b'f' => out.push('\u{000c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let code = self.parse_hex4()?;
                            if (0xD800..=0xDBFF).contains(&code) {
                                if self.bump() != Some(b'\\') || self.bump() != Some(b'u') {
                                    return Err(StaticConfigParseError::InvalidJsonValue);
                                }
                                let low = self.parse_hex4()?;
                                if !(0xDC00..=0xDFFF).contains(&low) {
                                    return Err(StaticConfigParseError::InvalidJsonValue);
                                }
                                let scalar = 0x10000
                                    + (((code as u32 - 0xD800) << 10) | (low as u32 - 0xDC00));
                                let ch = char::from_u32(scalar)
                                    .ok_or(StaticConfigParseError::InvalidJsonValue)?;
                                out.push(ch);
                            } else {
                                let ch = char::from_u32(code as u32)
                                    .ok_or(StaticConfigParseError::InvalidJsonValue)?;
                                out.push(ch);
                            }
                        }
                        _ => return Err(StaticConfigParseError::InvalidJsonValue),
                    }
                }
                0x00..=0x1F => return Err(StaticConfigParseError::InvalidJsonValue),
                _ => {
                    // Decode full UTF-8 char starting at `self.pos - 1`.
                    let start = self.pos - 1;
                    let rest = std::str::from_utf8(&self.bytes[start..])
                        .map_err(|_| StaticConfigParseError::InvalidJsonValue)?;
                    let ch = rest
                        .chars()
                        .next()
                        .ok_or(StaticConfigParseError::InvalidJsonValue)?;
                    out.push(ch);
                    self.pos = start + ch.len_utf8();
                }
            }
        }
        Err(StaticConfigParseError::Eof)
    }

    fn parse_hex4(&mut self) -> Result<u16, StaticConfigParseError> {
        if self.pos + 4 > self.bytes.len() {
            return Err(StaticConfigParseError::Eof);
        }
        let s = std::str::from_utf8(&self.bytes[self.pos..self.pos + 4])
            .map_err(|_| StaticConfigParseError::InvalidJsonValue)?;
        self.pos += 4;
        u16::from_str_radix(s, 16).map_err(|_| StaticConfigParseError::InvalidJsonValue)
    }

    fn consume_literal(&mut self, lit: &[u8]) -> bool {
        if self.bytes[self.pos..].starts_with(lit) {
            self.pos += lit.len();
            true
        } else {
            false
        }
    }

    fn skip_value(&mut self) -> Result<(), StaticConfigParseError> {
        self.skip_ws();
        let Some(b) = self.peek() else {
            return Err(StaticConfigParseError::Eof);
        };
        match b {
            b'"' => {
                self.parse_string()?;
                Ok(())
            }
            b'{' => {
                self.pos += 1;
                self.skip_ws();
                if self.peek() == Some(b'}') {
                    self.pos += 1;
                    return Ok(());
                }
                loop {
                    self.skip_ws();
                    self.parse_string()?;
                    self.skip_ws();
                    if self.bump() != Some(b':') {
                        return Err(StaticConfigParseError::ExpectedColon);
                    }
                    self.skip_value()?;
                    self.skip_ws();
                    match self.bump() {
                        Some(b',') => continue,
                        Some(b'}') => return Ok(()),
                        _ => return Err(StaticConfigParseError::ExpectedCommaOrClose),
                    }
                }
            }
            b'[' => {
                self.pos += 1;
                self.skip_ws();
                if self.peek() == Some(b']') {
                    self.pos += 1;
                    return Ok(());
                }
                loop {
                    self.skip_value()?;
                    self.skip_ws();
                    match self.bump() {
                        Some(b',') => continue,
                        Some(b']') => return Ok(()),
                        _ => return Err(StaticConfigParseError::ExpectedCommaOrClose),
                    }
                }
            }
            b't' => {
                if self.consume_literal(b"true") {
                    Ok(())
                } else {
                    Err(StaticConfigParseError::InvalidJsonValue)
                }
            }
            b'f' => {
                if self.consume_literal(b"false") {
                    Ok(())
                } else {
                    Err(StaticConfigParseError::InvalidJsonValue)
                }
            }
            b'n' => {
                if self.consume_literal(b"null") {
                    Ok(())
                } else {
                    Err(StaticConfigParseError::InvalidJsonValue)
                }
            }
            b'-' | b'0'..=b'9' => self.skip_number(),
            _ => Err(StaticConfigParseError::InvalidJsonValue),
        }
    }

    fn skip_number(&mut self) -> Result<(), StaticConfigParseError> {
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        match self.bump() {
            Some(b'0') => {}
            Some(b'1'..=b'9') => {
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.pos += 1;
                }
            }
            _ => return Err(StaticConfigParseError::InvalidJsonValue),
        }
        if self.peek() == Some(b'.') {
            self.pos += 1;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(StaticConfigParseError::InvalidJsonValue);
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(StaticConfigParseError::InvalidJsonValue);
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        Ok(())
    }
}
