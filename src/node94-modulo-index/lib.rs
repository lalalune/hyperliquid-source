#![no_std]
//! Value projection of node94 0x538c820 and its closed helper 0x5422e70.
//!
//! Ordinary immutable slices replace valid nonwrapping target memory. The
//! original pointer ABI, address faults and concurrent mutation are excluded.

const FACTOR: u32 = 0xc6a4_a793;

/// Hash the complete input with the wrapper's literal seed 0x18d. The final
/// one to three bytes are signed contributions; full words are little-endian.
pub fn hash_for_index(input: &[u8]) -> u32 {
    let mut value = (input.len() as u32).wrapping_mul(FACTOR) ^ 0x18d;
    let mut words = input.chunks_exact(4);
    for word in &mut words {
        value = value
            .wrapping_add(u32::from_le_bytes(word.try_into().unwrap()))
            .wrapping_mul(FACTOR);
        value ^= value >> 16;
    }
    let tail = words.remainder();
    if !tail.is_empty() {
        for (position, byte) in tail.iter().enumerate() {
            value = value.wrapping_add((i32::from(*byte as i8) as u32) << (position * 8));
        }
        value = value.wrapping_mul(FACTOR);
        value ^= value >> 24;
    }
    value
}

/// New safe API refusals, not recovered target return variants.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Refusal {
    ZeroDivisor,
    TableBounds,
}

/// Return the table byte at low32(raw_index) + (hash(input) mod divisor).
/// The source's zero divisor faults; this API reports ZeroDivisor instead.
/// TableBounds reports an absent byte without a native memory access.
pub fn lookup(input: &[u8], divisor: u16, table: &[u8], raw_index: u64) -> Result<u8, Refusal> {
    let hash = hash_for_index(input);
    if divisor == 0 {
        return Err(Refusal::ZeroDivisor);
    }
    let offset = u64::from(raw_index as u32) + u64::from(hash % u32::from(divisor));
    usize::try_from(offset)
        .ok()
        .and_then(|index| table.get(index))
        .copied()
        .ok_or(Refusal::TableBounds)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_tail_and_empty_seed() {
        assert_eq!(hash_for_index(&[]), 397);
        assert_eq!(hash_for_index(&[128]), 0xc5cd2b7f);
    }

    #[test]
    fn index_high_bits_and_exact_end() {
        let table = [9, 254, 255];
        assert_eq!(lookup(&[], 1, &table, (1 << 63) | 2), Ok(255));
        assert_eq!(lookup(&[], 1, &table, 3), Err(Refusal::TableBounds));
    }

    #[test]
    fn divisor_refusal_precedes_missing_table() {
        assert_eq!(
            lookup(&[255; 8], 0, &[], u64::MAX),
            Err(Refusal::ZeroDivisor)
        );
    }
}
