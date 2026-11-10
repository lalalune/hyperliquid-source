//! Node #115 BOLE user reply (0x38e5d00, read address 0x...0811): the gas charges, the check order, the two
//! 1e14 pair computations and the four reply words. The input parse, the token store search, the user map lookup
//! and the bytes constructor are not implemented here; their results are inputs.
//! Evidence: research/work-items/RE-004-bole-user-reply-115. Role names below are inference.
#![no_std]
#![forbid(unsafe_code)]

/// 1e14, the divisor and the bound on the high word of a product. The bytes show it as an immediate.
pub const E14: u64 = 100_000_000_000_000;
/// The constant part of the first charge (bytes show 1000).
pub const BASE_GAS: u64 = 1000;
/// Gas per byte, used for the input length and for the reply length (bytes show 33).
pub const GAS_PER_BYTE: u64 = 33;
/// Longest input accepted before parsing (bytes show a refusal above 2000).
pub const MAX_INPUT: u64 = 2000;
/// Length of the reply: four 32 byte words.
pub const REPLY_LEN: usize = 128;
/// Refusal code when the token index is not below the token count (bytes show 0xfa).
pub const CODE_TOKEN_RANGE: u8 = 0xfa;
/// Refusal code when the token or the user entry is missing (bytes show 0xf1).
pub const CODE_MISSING: u8 = 0xf1;

/// The first charge, or None when the body refuses before parsing: input longer than 2000 bytes,
/// or `1000 + 33 * input_len` above the limit.
pub fn first_charge(input_len: u64, gas_limit: u64) -> Option<u64> {
    if input_len > MAX_INPUT {
        return None;
    }
    let charge = BASE_GAS + GAS_PER_BYTE * input_len;
    (charge <= gas_limit).then_some(charge)
}

/// The whole charge once the reply exists, or None when it is above the limit.
/// `first + 33 * reply_len`, both the product and the sum saturating at `u64::MAX`.
pub fn whole_charge(first: u64, reply_len: u64, gas_limit: u64) -> Option<u64> {
    let total = first.saturating_add(GAS_PER_BYTE.saturating_mul(reply_len));
    (total <= gas_limit).then_some(total)
}

/// One pair computation. `p = v * field` as u128. The tag (inference: "fits") is
/// `(p >> 64) < 1e14`; when it is clear the result is None. Otherwise the quotient is the
/// low 64 bits of `floor(p / 1e14)`.
pub fn pair(v: u64, field: u64) -> Option<u64> {
    let p = u128::from(v) * u128::from(field);
    if (p >> 64) >= u128::from(E14) {
        return None;
    }
    Some((p / u128::from(E14)) as u64)
}

/// The four reply words. The first pair uses (`v8`, `f58`) and carries `v0`; the second uses
/// (`v18`, `f78`) and carries `v10`. A word pair is zero when its tag is clear.
pub fn reply_words(v0: u64, v8: u64, v10: u64, v18: u64, f58: u64, f78: u64) -> [u64; 4] {
    let (w0, w1) = match pair(v8, f58) {
        Some(q) => (v0, q),
        None => (0, 0),
    };
    let (w2, w3) = match pair(v18, f78) {
        Some(q) => (v10, q),
        None => (0, 0),
    };
    [w0, w1, w2, w3]
}

/// The 128 reply bytes: each word as a 32 byte big-endian value (24 zero bytes, then the u64 big-endian).
pub fn reply_bytes(words: [u64; 4]) -> [u8; REPLY_LEN] {
    let mut out = [0u8; REPLY_LEN];
    for (i, w) in words.iter().enumerate() {
        out[i * 32 + 24..i * 32 + 32].copy_from_slice(&w.to_be_bytes());
    }
    out
}

/// Everything the body reads, with the parse and the two lookups already resolved. Field names past the
/// offsets in the doc strings are inference.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Inputs {
    /// Input length in bytes.
    pub input_len: u64,
    /// The gas limit.
    pub gas_limit: u64,
    /// The length the bytes constructor reports for the reply (0x80 normally).
    pub reply_len: u64,
    /// Whether the parse succeeded.
    pub parse_ok: bool,
    /// Parsed token index (ignored when `parse_ok` is false).
    pub token: u64,
    /// Token count.
    pub count: u64,
    /// Whether the token store holds the token.
    pub token_found: bool,
    /// Whether the user entry exists and its map holds the token (a missing user key counts as not found).
    pub entry_found: bool,
    /// Map value u64 at +0.
    pub v0: u64,
    /// Map value u64 at +8.
    pub v8: u64,
    /// Map value u64 at +0x10.
    pub v10: u64,
    /// Map value u64 at +0x18.
    pub v18: u64,
    /// Token record u64 at +0x58.
    pub f58: u64,
    /// Token record u64 at +0x78.
    pub f78: u64,
}

/// How the body ends.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    /// Out of gas, at the first or the whole charge.
    OutOfGas,
    /// The parse failed; the refusal text is "Invalid input" (13 bytes).
    InvalidInput,
    /// Refusal with the given code (0xfa or 0xf1).
    Code(u8),
    /// A reply with the four words and the total gas charged.
    Reply {
        /// The total gas.
        total_gas: u64,
        /// The four reply words.
        words: [u64; 4],
    },
}

/// Applies the checks in the order the bytes show: first charge, parse, token >= count,
/// token found, entry found, pairs and reply, whole charge.
pub fn evaluate(i: &Inputs) -> Outcome {
    let Some(first) = first_charge(i.input_len, i.gas_limit) else {
        return Outcome::OutOfGas;
    };
    if !i.parse_ok {
        return Outcome::InvalidInput;
    }
    if i.token >= i.count {
        return Outcome::Code(CODE_TOKEN_RANGE);
    }
    if !i.token_found || !i.entry_found {
        return Outcome::Code(CODE_MISSING);
    }
    let words = reply_words(i.v0, i.v8, i.v10, i.v18, i.f58, i.f78);
    match whole_charge(first, i.reply_len, i.gas_limit) {
        Some(total_gas) => Outcome::Reply { total_gas, words },
        None => Outcome::OutOfGas,
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::collections::BTreeMap;
    use std::string::String;
    use std::vec::Vec;

    fn num(s: &str) -> u64 {
        if s == "-" {
            0
        } else {
            s.parse().expect("decimal u64")
        }
    }

    fn hex(b: &[u8]) -> String {
        use std::fmt::Write;
        let mut s = String::new();
        for x in b {
            write!(s, "{x:02x}").unwrap();
        }
        s
    }

    #[test]
    fn vectors() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../research/work-items/RE-004-bole-user-reply-115/rust-vectors.tsv"
        );
        let text = std::fs::read_to_string(path).expect("vectors file");
        let mut lines = text
            .lines()
            .filter(|l| !l.starts_with('#') && !l.is_empty());
        let header: Vec<&str> = lines.next().expect("column row").split('\t').collect();
        assert_eq!(header.len(), 22);
        let mut counts: BTreeMap<String, usize> = BTreeMap::new();
        for line in lines {
            let c: Vec<&str> = line.split('\t').collect();
            assert_eq!(c.len(), 22, "{line}");
            let inp = Inputs {
                input_len: num(c[1]),
                gas_limit: num(c[2]),
                reply_len: num(c[3]),
                parse_ok: c[4] == "1",
                token: num(c[5]),
                count: num(c[6]),
                token_found: c[7] == "1",
                entry_found: c[8] == "1",
                v0: num(c[9]),
                v8: num(c[10]),
                v10: num(c[11]),
                v18: num(c[12]),
                f58: num(c[13]),
                f78: num(c[14]),
            };
            let got = evaluate(&inp);
            let ctx = c[0];
            match c[15] {
                "out_of_gas" => assert_eq!(got, Outcome::OutOfGas, "{ctx}: {line}"),
                "invalid_input" => assert_eq!(got, Outcome::InvalidInput, "{ctx}"),
                "code_fa" => assert_eq!(got, Outcome::Code(0xfa), "{ctx}"),
                "code_f1" => assert_eq!(got, Outcome::Code(0xf1), "{ctx}"),
                "reply" => {
                    let words = [num(c[17]), num(c[18]), num(c[19]), num(c[20])];
                    assert_eq!(
                        got,
                        Outcome::Reply {
                            total_gas: num(c[16]),
                            words
                        },
                        "{ctx}: {line}"
                    );
                    assert_eq!(hex(&reply_bytes(words)), c[21], "{ctx}");
                }
                other => panic!("unknown outcome {other}"),
            }
            *counts.entry(c[15].into()).or_default() += 1;
        }
        let total: usize = counts.values().sum();
        assert!(total >= 100, "only {total} rows");
        for (k, v) in &counts {
            std::println!("{k}: {v}");
        }
        std::println!("total: {total}");
    }

    #[test]
    fn first_charge_bounds() {
        assert_eq!(first_charge(2000, u64::MAX), Some(67_000));
        assert_eq!(first_charge(2001, u64::MAX), None);
        assert_eq!(first_charge(0, 1000), Some(1000));
        assert_eq!(first_charge(0, 999), None);
        assert_eq!(first_charge(2000, 67_000), Some(67_000));
        assert_eq!(first_charge(2000, 66_999), None);
    }

    #[test]
    fn whole_charge_bounds_and_saturation() {
        assert_eq!(whole_charge(1000, 128, 5224), Some(5224));
        assert_eq!(whole_charge(1000, 128, 5223), None);
        assert_eq!(whole_charge(1000, u64::MAX, u64::MAX), Some(u64::MAX));
        assert_eq!(whole_charge(1000, u64::MAX, u64::MAX - 1), None);
        assert_eq!(whole_charge(u64::MAX, 1, u64::MAX), Some(u64::MAX));
    }

    #[test]
    fn pair_tag_and_floor() {
        // Exact construction with v = 2^63: p = field << 63, high word = field >> 1.
        assert!(pair(1 << 63, 2 * (E14 - 1) + 1).is_some());
        assert!(pair(1 << 63, 2 * E14).is_none());
        // Floor rounding.
        assert_eq!(pair(1, E14 - 1), Some(0));
        assert_eq!(pair(1, E14), Some(1));
        assert_eq!(pair(3, E14 / 2 + 1), Some(1));
        assert_eq!(pair(0, u64::MAX), Some(0));
    }

    #[test]
    fn words_and_bytes() {
        let w = reply_words(7, E14, 9, 2 * E14, 3, 1 << 63);
        assert_eq!(w[..2], [7, 3]);
        let w = reply_words(7, 1 << 63, 9, 1, 2 * E14, 5);
        assert_eq!(w, [0, 0, 9, 0]);
        let b = reply_bytes([1, 2, 3, u64::MAX]);
        assert_eq!(b[31], 1);
        assert_eq!(b[63], 2);
        assert_eq!(b[95], 3);
        assert_eq!(b[96..120], [0u8; 24]);
        assert_eq!(b[120..], [0xff; 8]);
    }

    #[test]
    fn check_order() {
        let base = Inputs {
            input_len: 0,
            gas_limit: u64::MAX,
            reply_len: 128,
            parse_ok: false,
            token: 5,
            count: 1,
            token_found: false,
            entry_found: false,
            v0: 1,
            v8: 2,
            v10: 3,
            v18: 4,
            f58: E14,
            f78: E14,
        };
        assert_eq!(evaluate(&base), Outcome::InvalidInput);
        let b = Inputs {
            parse_ok: true,
            ..base
        };
        assert_eq!(evaluate(&b), Outcome::Code(0xfa));
        let b = Inputs { token: 0, ..b };
        assert_eq!(evaluate(&b), Outcome::Code(0xf1));
        let b = Inputs {
            token_found: true,
            entry_found: true,
            ..b
        };
        assert_eq!(
            evaluate(&b),
            Outcome::Reply {
                total_gas: 5224,
                words: [1, 2, 3, 4]
            }
        );
        assert_eq!(
            evaluate(&Inputs {
                input_len: 2001,
                ..base
            }),
            Outcome::OutOfGas
        );
    }
}
