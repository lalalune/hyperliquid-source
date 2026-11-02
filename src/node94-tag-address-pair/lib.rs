#![no_std]
#![forbid(unsafe_code)]

/// Numeric values of the target's two claimed output registers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Registers {
    pub rax: u64,
    pub rdx: u64,
}

/// Project node94 ELF VA `0x15d65b0..0x15d65f3` from a supplied qword snapshot.
///
/// `object` is the original RDI bit pattern, `tag` is the qword read there, and
/// `load_bias` is the common image bias. This function accepts all numeric u64
/// values; it neither validates nor dereferences an address. Native execution
/// correspondence requires an ordinary readable qword matching `tag`, mapped
/// code/control memory and no concurrent changes. The returned addresses name
/// slots themselves, not their relocated contents. No pointer ABI is claimed.
#[must_use]
pub const fn select(object: u64, tag: u64, load_bias: u64) -> Registers {
    const HALF: u64 = 1 << 63;
    if tag < HALF {
        Registers {
            rax: object,
            rdx: load_bias.wrapping_add(0x5676c20),
        }
    } else if tag == HALF {
        Registers {
            rax: object.wrapping_add(8),
            rdx: load_bias.wrapping_add(0x5676ba8),
        }
    } else if tag == HALF + 1 {
        Registers {
            rax: 0,
            rdx: HALF + 1,
        }
    } else {
        Registers {
            rax: 0,
            rdx: HALF + 2,
        }
    }
}
