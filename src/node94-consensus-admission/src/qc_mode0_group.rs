//! Qualified full-word-zero state projection of node94 `0x466bf60`.
//!
//! The accepted scalar markers are 0..=FA, FB, FC and FD, with little-endian
//! payloads. This four-call composition exposes final cursor/value/short-input
//! effects only. It does not reconstruct the original decoder ABI, constructor,
//! inactive error bytes, stack lifetime or complete QC row reachability.

/// Chosen safe result type; its Rust layout is unrelated to native storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode0GroupOutcome {
    /// Wrong full mode word or an unsupported marker before completion/short.
    /// The chosen API leaves all arguments unchanged outside its domain.
    OutsideDomain,
    Complete([u64; 4]),
    Incomplete { needed: u64 },
}

impl Mode0GroupOutcome {
    /// Observed group tag qword, kind byte and need qword for qualified shorts.
    /// Neither inactive error bytes nor original error layout are exposed.
    pub fn observed_short_fields(&self) -> Option<(u64, u8, u64)> {
        match self {
            Self::Incomplete { needed } => Some((1, 0, *needed)),
            _ => None,
        }
    }
}

// Qualification is separate from consumption so API exclusions are atomic.
fn accepted_prefix(mut input: &[u8]) -> bool {
    for _ in 0..4 {
        let Some(&marker) = input.first() else { return true; };
        let total = match marker {
            0..=0xfa => 1,
            0xfb => 3,
            0xfc => 5,
            0xfd => 9,
            _ => return false,
        };
        if input.len() < total { return true; }
        input = &input[total..];
    }
    true
}

/// Read four accepted words, or stop at the first qualified short/empty input.
///
/// The complete eight-byte mode word must be zero. Under that premise native
/// reserve/refund paths and scalar charging are bypassed: charge and limit may
/// be arbitrary, including charge MAX with limit zero. This implementation
/// therefore does not inspect or update either argument. Small/nonminimal
/// integer encodings are accepted. A short marked value consumes only its
/// marker; empty input consumes nothing further. These are final-state effects,
/// not a claim about target ABI, instruction timing or row admission.
pub fn read_mode0_group(
    mode_word: u64,
    _charge: &mut u64,
    _limit: u64,
    input: &mut &[u8],
) -> Mode0GroupOutcome {
    if mode_word != 0 || !accepted_prefix(input) {
        return Mode0GroupOutcome::OutsideDomain;
    }
    let mut words = [0u64; 4];
    for index in 0..4 {
        let Some(&marker) = input.first() else {
            return Mode0GroupOutcome::Incomplete { needed: 1 };
        };
        let payload = match marker {
            0..=0xfa => 0,
            0xfb => 2,
            0xfc => 4,
            0xfd => 8,
            _ => return Mode0GroupOutcome::OutsideDomain,
        };
        let total = payload + 1;
        if input.len() < total {
            let needed = (total - input.len()) as u64;
            *input = &input[1..];
            return Mode0GroupOutcome::Incomplete { needed };
        }
        let value = match payload {
            0 => marker as u64,
            2 => u16::from_le_bytes(input[1..3].try_into().unwrap()) as u64,
            4 => u32::from_le_bytes(input[1..5].try_into().unwrap()) as u64,
            8 => u64::from_le_bytes(input[1..9].try_into().unwrap()),
            _ => unreachable!(),
        };
        words[index] = value;
        *input = &input[total..];
    }
    Mode0GroupOutcome::Complete(words)
}
