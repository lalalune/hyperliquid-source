#![no_std]
#![forbid(unsafe_code)]
//! Value projection of node #94 [0x14b4e20, 0x14b4e48).
//! Numeric addresses use a caller-supplied load bias; they are never dereferenced.

/// The four general registers written by the captured leaf, at normal return.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Registers {
    pub rax: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rsi: u64,
}

/// `tag` is the value of the original one-byte read through RDI.
/// All 256 values and every numeric `load_bias` are accepted.
pub fn select(tag: u8, load_bias: u64) -> Registers {
    let value = u64::from(tag);
    let length = (value ^ 1) * 3 + 14;
    let first = load_bias.wrapping_add(0x21bf92);
    let second = load_bias.wrapping_add(0x21bfa3);
    Registers {
        rax: if value == 0 { first } else { second },
        rdx: length,
        rcx: value,
        rsi: second,
    }
}

/// A separate byte-view adapter, not a memory operation performed by the leaf.
/// `window` represents the unchanged captured bytes [0x21bf92, 0x21c2ae).
/// It is indexed independently of any numeric load bias or host pointer.
pub fn captured_bytes(tag: u8, window: &[u8; 796]) -> &[u8] {
    let start = if tag == 0 { 0 } else { 17 };
    let length = select(tag, 0).rdx as usize;
    &window[start..start + length]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maximum_is_at_254_not_255() {
        assert_eq!(select(254, 0).rdx, 779);
        assert_eq!(select(255, 0).rdx, 776);
        assert_eq!(select(128, 0).rcx, 128);
    }

    #[test]
    fn numeric_pointer_wrap_and_unconditional_rsi() {
        let bias = 0u64.wrapping_sub(0x21bfa3);
        let a = select(0, bias);
        assert_eq!(a.rax, u64::MAX - 16);
        assert_eq!(a.rsi, 0);
        assert_eq!(select(1, bias).rax, 0);
    }

    #[test]
    fn views_reach_the_exact_last_byte() {
        let mut window = [0; 796];
        window[0] = 11;
        window[17] = 22;
        window[795] = 33;
        assert_eq!(captured_bytes(0, &window)[0], 11);
        assert_eq!(captured_bytes(1, &window)[0], 22);
        assert_eq!(captured_bytes(254, &window)[778], 33);
    }
}
