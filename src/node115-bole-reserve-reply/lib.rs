//! Node #115 BOLE reserve reply (0x38e64b0, read address 0x...0812): the gas charge and the eight reply words,
//! with the utilization and two slope rate arithmetic of 0x36a08b0, 0x36a09f0 and 0x36a0b30 that the words use.
//! The token parse, the store search, the two message builders and the bytes constructor are not implemented here.
//! Evidence: research/work-items/RE-004-bole-reserve-reply-115.
#![no_std]
#![forbid(unsafe_code)]

pub const E10: u64 = 10_000_000_000;
pub const E14: u64 = 100_000_000_000_000;
pub const BASE_GAS: u64 = 1000;
pub const GAS_PER_BYTE: u64 = 33;
pub const MAX_INPUT: u64 = 2000;
pub const REPLY_BYTES: usize = 0x100;

/// The fields 0x38e64b0 and its callees read from one 0xb0 byte token record. Names past the offsets are inference.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Record {
    /// dword at +0x00; only the value 1 makes `optional` count
    pub tag: u32,
    /// +0x08
    pub optional: u64,
    /// +0x10
    pub plus_10: u64,
    /// +0x18
    pub plus_18: u64,
    /// +0x40 and +0x58: their product is the borrowed total scaled by 1e14
    pub a: u64,
    pub ia: u64,
    /// +0x60 and +0x78: their product is the supplied total scaled by 1e14
    pub b: u64,
    pub ib: u64,
    /// +0x80, +0x88, +0x90, +0x98
    pub min: u64,
    pub max: u64,
    pub bend: u64,
    pub kink: u64,
}

/// The first charge, or None when the body refuses before parsing (input too long, or the charge is above the limit).
pub fn first_charge(input_len: u64, gas_limit: u64) -> Option<u64> {
    if input_len > MAX_INPUT {
        return None;
    }
    let charge = BASE_GAS + GAS_PER_BYTE * input_len;
    (charge <= gas_limit).then_some(charge)
}

/// The whole charge once the reply exists, or None when it is above the limit. Both steps saturate.
pub fn whole_charge(first: u64, reply_len: u64, gas_limit: u64) -> Option<u64> {
    let total = first.saturating_add(GAS_PER_BYTE.saturating_mul(reply_len));
    (total <= gas_limit).then_some(total)
}

fn borrowed_total(rec: &Record) -> u128 {
    let product = rec.a as u128 * rec.ia as u128;
    product / E14 as u128 + !product.is_multiple_of(E14 as u128) as u128
}

/// Utilization scaled by 1e14 and capped there, or the refusal code of the two Result bodies.
pub fn utilization(rec: &Record) -> Result<u64, u8> {
    let total = borrowed_total(rec);
    let error = if total >> 64 != 0 {
        Some(3)
    } else if rec.a == 0 && total != 0 {
        Some(2)
    } else {
        None
    };
    let product = rec.b as u128 * rec.ib as u128;
    let supplied = product / E14 as u128;
    if (product >> 64) as u64 > E14 - 1 {
        return Err(error.unwrap_or(3));
    }
    if let Some(code) = error {
        return Err(code);
    }
    if supplied as u64 == 0 {
        return Ok(0);
    }
    let ratio = (total as u64 as u128 * E14 as u128) / supplied;
    if ratio >> 64 != 0 {
        return Err(3);
    }
    Ok((ratio as u64).min(E14))
}

fn arm(fraction: u128, base: u64, end: u64) -> u64 {
    if end < base || fraction >> 64 != 0 {
        return end;
    }
    let product = fraction as u64 as u128 * (end - base) as u128;
    if product >= (E14 as u128) << 64 {
        return end;
    }
    let step = (product / E14 as u128) as u64;
    base.checked_add(step).unwrap_or(end)
}

/// The rate scaled by 1e14: `min` at no use, `bend` at `kink`, `max` at full use, straight lines between.
pub fn rate(rec: &Record) -> u64 {
    let used = utilization(rec).unwrap_or(0);
    if used == rec.kink {
        return rec.bend;
    }
    if used < rec.kink {
        return arm(
            used as u128 * E14 as u128 / rec.kink as u128,
            rec.min,
            rec.bend,
        );
    }
    if rec.kink > E14 - 1 {
        return rec.max;
    }
    arm(
        (used - rec.kink) as u128 * E14 as u128 / (E14 - rec.kink) as u128,
        rec.bend,
        rec.max,
    )
}

/// Word 1: the rate word (its low 32 bits, read as signed) times the utilization as f64 times (1 - reserve / 1e14).
pub fn supply_rate(rate_word: u64, utilization_f64: f64, reserve: u64) -> u64 {
    let value = (reserve as f64 / -1e14 + 1.0) * (rate_word as u32 as i32 as f64 * utilization_f64);
    if value.is_finite() { value as u64 } else { 0 }
}

fn guarded(left: u64, right: u64) -> u64 {
    let product = left as u128 * right as u128;
    if (product >> 64) as u64 > E14 - 1 {
        0
    } else {
        (product / E14 as u128) as u64
    }
}

/// The eight reply words in order, or None where the body answers with its second refusal message (a utilization refusal).
pub fn reply_words(rec: &Record, reserve: u64) -> Option<[u64; 8]> {
    let rate_word = rate(rec) / E10;
    let used = utilization(rec).ok()?;
    Some([
        rate_word,
        supply_rate(rate_word, used as f64 / 1e14, reserve),
        rec.plus_18,
        used / E10,
        rec.plus_10,
        if rec.tag == 1 { rec.optional / E10 } else { 0 },
        guarded(rec.b, rec.ib),
        guarded(rec.a, rec.ia),
    ])
}

/// Each word as 32 big-endian bytes.
pub fn reply_bytes(words: &[u64; 8]) -> [u8; REPLY_BYTES] {
    let mut out = [0u8; REPLY_BYTES];
    for (index, word) in words.iter().enumerate() {
        out[index * 32 + 24..index * 32 + 32].copy_from_slice(&word.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Inputs and reply words read from runs of the node #115 bytes (tools/bole_reserve_reply115.py).
    const VECTORS: &str =
        include_str!("../../research/work-items/RE-004-bole-reserve-reply-115/rust-vectors.tsv");

    fn rows() -> impl Iterator<Item = (Record, u64, Option<[u64; 8]>)> {
        VECTORS.lines().skip(1).map(|line| {
            let mut cells = line.split('\t');
            let mut next = || cells.next().unwrap().parse::<u64>().unwrap();
            let rec = Record {
                tag: next() as u32,
                optional: next(),
                plus_10: next(),
                plus_18: next(),
                a: next(),
                ia: next(),
                b: next(),
                ib: next(),
                min: next(),
                max: next(),
                bend: next(),
                kink: next(),
            };
            let reserve = next();
            let last = cells.next().unwrap();
            assert!(cells.next().is_none());
            let words = (last != "refused").then(|| {
                let mut words = [0u64; 8];
                let mut parts = last.split(' ');
                for word in words.iter_mut() {
                    *word = parts.next().unwrap().parse().unwrap();
                }
                assert!(parts.next().is_none());
                words
            });
            (rec, reserve, words)
        })
    }

    #[test]
    fn every_vector_from_the_target_bytes_matches() {
        let (mut total, mut refused) = (0, 0);
        for (rec, reserve, want) in rows() {
            assert_eq!(
                reply_words(&rec, reserve),
                want,
                "{rec:?} reserve {reserve}"
            );
            total += 1;
            refused += want.is_none() as u32;
        }
        assert!(
            total >= 400 && refused >= 50 && total - refused >= 300,
            "{total} {refused}"
        );
    }

    #[test]
    fn a_changed_input_is_noticed() {
        // corruption control: the vectors must be able to fail
        let (mut reserve_seen, mut share_seen) = (0, 0);
        for (rec, reserve, want) in rows() {
            let Some(words) = want else { continue };
            if words[1] > 1000 && reserve < E14 / 2 {
                assert_ne!(reply_words(&rec, reserve + E14 / 2), want);
                reserve_seen += 1;
            }
            if words[7] > 0 && words[7] < u64::MAX / 4 && rec.ia == E14 {
                assert_ne!(
                    reply_words(
                        &Record {
                            a: rec.a * 2 + 1,
                            ..rec
                        },
                        reserve
                    ),
                    want
                );
                share_seen += 1;
            }
        }
        assert!(
            reserve_seen >= 20 && share_seen >= 20,
            "{reserve_seen} {share_seen}"
        );
    }

    #[test]
    fn worked_example() {
        let rec = Record {
            tag: 1,
            optional: 8 * E14 / 10,
            plus_10: 3,
            plus_18: 4,
            a: 50,
            ia: E14,
            b: 100,
            ib: E14,
            min: 0,
            max: E14,
            bend: 5 * E14 / 100,
            kink: 8 * E14 / 10,
        };
        assert_eq!(
            reply_words(&rec, E14 / 10),
            Some([312, 140, 4, 5000, 3, 8000, 100, 50])
        );
        let bytes = reply_bytes(&[312, 140, 4, 5000, 3, 8000, 100, 50]);
        assert_eq!(
            &bytes[..32],
            &[
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 1, 0x38
            ]
        );
        assert_eq!(bytes[0xff], 50);
    }

    #[test]
    fn charges() {
        assert_eq!(first_charge(0, 1000), Some(1000));
        assert_eq!(first_charge(0, 999), None);
        assert_eq!(first_charge(2000, u64::MAX), Some(67_000));
        assert_eq!(first_charge(2001, u64::MAX), None);
        assert_eq!(whole_charge(2056, 0x100, 10_504), Some(10_504));
        assert_eq!(whole_charge(2056, 0x100, 10_503), None);
        assert_eq!(whole_charge(2056, u64::MAX / 33, u64::MAX), Some(u64::MAX));
        assert_eq!(whole_charge(2056, u64::MAX, u64::MAX - 1), None);
    }

    #[test]
    fn supply_rate_edges() {
        assert_eq!(supply_rate(4096, 1.0, 0), 4096);
        assert_eq!(supply_rate(4096, 1.0, E14), 0);
        assert_eq!(supply_rate(4096, 1.0, 3 * E14), 0);
        assert_eq!(supply_rate(1 << 31, 1.0, 0), 0);
        assert_eq!(supply_rate((1 << 32) + 5, 1.0, 0), 5);
        assert_eq!(supply_rate(4096, f64::NAN, 0), 0);
        assert_eq!(supply_rate(4096, f64::INFINITY, 0), 0);
        assert_eq!(supply_rate(1, f64::MAX, 0), u64::MAX);
        assert_eq!(
            supply_rate(4096, 18446744073709551616.0 / 4096.0, 0),
            u64::MAX
        );
        assert_eq!(
            supply_rate(4096, 18446744073709549568.0 / 4096.0, 0),
            18446744073709549568
        );
    }
}
