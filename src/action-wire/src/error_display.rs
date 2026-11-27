//! Action error Display template byte decoder and verified tag constants (`0x46ef710`).
//!
//! Anchored to `research/work-items/action-wire-error-display-115`
//! (418 tags `0..=417`, 337 static strings + 81 templates, 12,540 cases, 0 mismatches).

/// Total number of error tag arms in node #115's Display table `0x7d8c1c`.
pub const ERROR_TAG_COUNT: usize = 418;

/// Success discriminant immediately past the 418-entry error table (`0x1a2` = 418).
pub const ACTION_SUCCESS_TAG: u16 = 0x1a2;

/// Core wire, replay, signature, and expiry error tags verified in `0x46ef710`.
pub const TAG_NONCE_ALREADY_USED: u16 = 93;
pub const TAG_NONCE_MISMATCH: u16 = 96;
pub const TAG_TOO_MANY_PENDING_NONCES: u16 = 97;
pub const TAG_MAINNET_TESTNET_SIGNATURE: u16 = 147;
pub const TAG_MANUAL_UNJAIL_COOLDOWN: u16 = 159;
pub const TAG_NONCE_TOO_LOW: u16 = 203;
pub const TAG_NONCE_TOO_HIGH: u16 = 204;
pub const TAG_NONCE_DUPLICATE: u16 = 205;
pub const TAG_ACTION_ALREADY_EXPIRED: u16 = 208;

/// Decoded piece of a node #115 Rust `core::fmt::Arguments` template byte string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TemplatePiece<'a> {
    Literal(&'a [u8]),
    Argument,
}

/// Errors returned when decoding a malformed template byte slice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TemplateDecodeError {
    TruncatedLongLength,
    TruncatedLiteral { expected: usize, available: usize },
    UnexpectedOpcode(u8),
}

/// Decodes a node #115 Display template byte stream (`0x1680500` grammar):
/// - `0x00`: terminator
/// - `0x01..=0x7f`: short literal of that byte length
/// - `0x80`: long literal followed by little-endian `u16` length (used by tag 82)
/// - `0xc0`: next argument slot (`{}`)
pub fn decode_template(bytes: &[u8]) -> Result<Vec<TemplatePiece<'_>>, TemplateDecodeError> {
    let mut pieces = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        let op = bytes[i];
        i += 1;
        match op {
            0x00 => break,
            0x01..=0x7f => {
                let len = usize::from(op);
                if i + len > bytes.len() {
                    return Err(TemplateDecodeError::TruncatedLiteral {
                        expected: len,
                        available: bytes.len() - i,
                    });
                }
                pieces.push(TemplatePiece::Literal(&bytes[i..i + len]));
                i += len;
            }
            0x80 => {
                if i + 2 > bytes.len() {
                    return Err(TemplateDecodeError::TruncatedLongLength);
                }
                let len = usize::from(u16::from_le_bytes([bytes[i], bytes[i + 1]]));
                i += 2;
                if i + len > bytes.len() {
                    return Err(TemplateDecodeError::TruncatedLiteral {
                        expected: len,
                        available: bytes.len() - i,
                    });
                }
                pieces.push(TemplatePiece::Literal(&bytes[i..i + len]));
                i += len;
            }
            0xc0 => pieces.push(TemplatePiece::Argument),
            other => return Err(TemplateDecodeError::UnexpectedOpcode(other)),
        }
    }
    Ok(pieces)
}

/// Renders a decoded template by substituting formatted `args` for `{}` placeholders.
pub fn render_template(bytes: &[u8], args: &[&str]) -> Result<String, TemplateDecodeError> {
    let pieces = decode_template(bytes)?;
    let mut out = String::new();
    let mut arg_idx = 0usize;
    for piece in pieces {
        match piece {
            TemplatePiece::Literal(lit) => out.push_str(&String::from_utf8_lossy(lit)),
            TemplatePiece::Argument => {
                if let Some(val) = args.get(arg_idx) {
                    out.push_str(val);
                } else {
                    out.push_str("{}");
                }
                arg_idx += 1;
            }
        }
    }
    Ok(out)
}

/// Returns the verified static or template-hole text for core wire/replay/signing tags.
pub const fn known_wire_error_text(tag: u16) -> Option<&'static str> {
    match tag {
        TAG_NONCE_ALREADY_USED => Some("Nonce already used."),
        TAG_NONCE_MISMATCH => Some("Nonce mismatch."),
        TAG_TOO_MANY_PENDING_NONCES => Some("Too many pending nonces"),
        TAG_MAINNET_TESTNET_SIGNATURE => Some("Mainnet and testnet require different signature."),
        TAG_MANUAL_UNJAIL_COOLDOWN => Some("Can only manually unjail once every {} seconds"),
        TAG_NONCE_TOO_LOW => Some("Invalid nonce: nonce too low {} < {}"),
        TAG_NONCE_TOO_HIGH => Some("Invalid nonce: nonce too high {} > {}"),
        TAG_NONCE_DUPLICATE => Some("Invalid nonce: duplicate nonce {}"),
        TAG_ACTION_ALREADY_EXPIRED => Some("Action already expired"),
        _ => None,
    }
}
