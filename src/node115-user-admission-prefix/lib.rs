#![no_std]
#![forbid(unsafe_code)]
//! Logical first-call/RET relation, never a complete user operation or native ABI.
const LIMIT: u64 = 0x0ccc_cccc_cccc_cccc;
pub struct Input<'a> {
    pub descriptor: &'a [u8; 99],
    pub active: u8,
    pub mode: u8,
    pub budget: u64,
    pub aux: u8,
    pub height: u64,
    pub counts: &'a [u16],
    pub identity: [u8; 20],
    pub context: [u8; 12],
}
#[derive(Debug, PartialEq, Eq)]
pub enum Frontier {
    Returned,
    Identity {
        encoded: u64,
        mode: u8,
        operation: u8,
        peer: [u8; 20],
        identity: [u8; 20],
    },
    Compare {
        encoded: u64,
        node: usize,
        height: u64,
        remaining_bytes: u64,
    },
    Budget {
        encoded: u64,
        mode: u8,
        amount: u64,
        budget: u64,
    },
    Operation {
        encoded: u64,
        mode: u8,
        context: [u8; 12],
    },
}
#[derive(Debug, PartialEq, Eq)]
pub struct Observation {
    pub output: [u8; 16],
    pub frontier: Frontier,
}
fn word(bytes: &[u8; 99], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}
fn returned(seed: u8, code: u16, payload: Option<u64>) -> Observation {
    let mut output = [seed; 16];
    output[..2].copy_from_slice(&code.to_le_bytes());
    if let Some(value) = payload {
        output[8..16].copy_from_slice(&value.to_le_bytes());
    }
    Observation {
        output,
        frontier: Frontier::Returned,
    }
}
fn pending(seed: u8, frontier: Frontier) -> Observation {
    Observation {
        output: [seed; 16],
        frontier,
    }
}
/// Raw descriptor fields overlap by construction. `counts` names only the
/// empty-child0 metadata chain before the first comparison; missing metadata
/// yields an own refusal, not native malformed-pointer or error behavior.
pub fn classify(input: &Input<'_>, seed: u8) -> Option<Observation> {
    let raw = word(input.descriptor, 0);
    let encoded = if raw & (1 << 63) == 0 {
        0
    } else {
        raw.wrapping_add(0x8000_0000_0000_0001)
    };
    if encoded == 2 {
        return Some(returned(seed, 0x92, None));
    }
    if input.active == 0 {
        if input.counts.is_empty() {
            return Some(returned(seed, 0x98, None));
        }
        let mut node = 0;
        let mut height = input.height;
        loop {
            let count = *input.counts.get(node)?;
            if count != 0 {
                let remaining_bytes = u64::from(count) * 20;
                return Some(pending(
                    seed,
                    Frontier::Compare {
                        encoded,
                        node,
                        height,
                        remaining_bytes,
                    },
                ));
            }
            if height == 0 {
                return Some(returned(seed, 0x98, None));
            }
            height -= 1;
            node += 1;
        }
    }
    if encoded != 0 {
        let operation = input.descriptor[0x48];
        if input.descriptor[0x4e] & 1 != 0 {
            return Some(pending(
                seed,
                Frontier::Identity {
                    encoded,
                    mode: input.mode,
                    operation,
                    peer: input.descriptor[0x4f..0x63].try_into().unwrap(),
                    identity: input.identity,
                },
            ));
        }
        if input.mode == 0 && operation & 1 != 0 {
            return Some(returned(seed, 0x92, None));
        }
    } else {
        if input.mode == 0 {
            return Some(returned(seed, 0x92, None));
        }
        let amount = word(input.descriptor, 0x58);
        if amount >= LIMIT {
            return Some(returned(seed, 0x154, Some(amount)));
        }
        if (amount | input.budget) != 0 {
            if input.descriptor[0x50] != 0 {
                return Some(returned(seed, 0x10c, None));
            }
            if input.aux == 0 {
                return Some(returned(seed, 0x10a, None));
            }
            return Some(pending(
                seed,
                Frontier::Budget {
                    encoded,
                    mode: input.mode,
                    amount,
                    budget: input.budget,
                },
            ));
        }
    }
    Some(pending(
        seed,
        Frontier::Operation {
            encoded,
            mode: input.mode,
            context: input.context,
        },
    ))
}
