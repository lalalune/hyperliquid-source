//! Encoder for the bounded node #115 signed-action body at VA 0x2406120.

pub const TARGET_SHA256: &str = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContainerMode {
    Map,
    Array,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HyperliquidChain {
    Local,
    Sandbox,
    Testnet,
    Mainnet,
}

impl HyperliquidChain {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Local => "Local",
            Self::Sandbox => "Sandbox",
            Self::Testnet => "Testnet",
            Self::Mainnet => "Mainnet",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FourFieldAction<'a> {
    pub tag_key: &'a str,
    pub variant: &'a str,
    pub signature_chain_id: [u8; 32],
    pub chain: HyperliquidChain,
    pub wei: u64,
    pub nonce: u64,
}

/// Encode the complete body at VA `0x2406120`, preserving a caller-owned prefix.
/// `signature_chain_id` is the target's 32-byte little-endian U256 storage form.
/// The target's exact serializer tag and variant strings are supplied by caller.
pub fn encode_body(prefix: &[u8], mode: ContainerMode, action: FourFieldAction<'_>) -> Vec<u8> {
    let mut out = Vec::with_capacity(prefix.len() + 96);
    out.extend_from_slice(prefix);
    match mode {
        ContainerMode::Map => out.push(0x85), // variant plus four named fields
        ContainerMode::Array => out.push(0x95),
    }
    if mode == ContainerMode::Map {
        write_str(&mut out, action.tag_key.as_bytes());
        write_str(&mut out, action.variant.as_bytes());
    } else {
        write_str(&mut out, action.variant.as_bytes());
    }
    field_str(
        &mut out,
        mode,
        "signatureChainId",
        &u256_hex(action.signature_chain_id),
    );
    field_str(
        &mut out,
        mode,
        "hyperliquidChain",
        action.chain.as_str().as_bytes(),
    );
    field_u64(&mut out, mode, "wei", action.wei);
    field_u64(&mut out, mode, "nonce", action.nonce);
    out
}

fn field_str(out: &mut Vec<u8>, mode: ContainerMode, key: &str, value: &[u8]) {
    if mode == ContainerMode::Map {
        write_str(out, key.as_bytes());
    }
    write_str(out, value);
}

fn field_u64(out: &mut Vec<u8>, mode: ContainerMode, key: &str, value: u64) {
    if mode == ContainerMode::Map {
        write_str(out, key.as_bytes());
    }
    write_u64(out, value);
}

fn write_str(out: &mut Vec<u8>, value: &[u8]) {
    let len = value.len();
    if len < 32 {
        out.push(0xa0 | len as u8);
    } else if len < 256 {
        out.extend_from_slice(&[0xd9, len as u8]);
    } else if len < 65_536 {
        out.push(0xda);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        out.push(0xdb);
        out.extend_from_slice(&(len as u32).to_be_bytes());
    }
    out.extend_from_slice(value);
}

fn write_u64(out: &mut Vec<u8>, value: u64) {
    match value {
        0..=0x7f => out.push(value as u8),
        0x80..=0xff => out.extend_from_slice(&[0xcc, value as u8]),
        0x100..=0xffff => {
            out.push(0xcd);
            out.extend_from_slice(&(value as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(0xce);
            out.extend_from_slice(&(value as u32).to_be_bytes());
        }
        _ => {
            out.push(0xcf);
            out.extend_from_slice(&value.to_be_bytes());
        }
    }
}

fn u256_hex(little_endian: [u8; 32]) -> Vec<u8> {
    let mut first = 0;
    while first < little_endian.len() && little_endian[31 - first] == 0 {
        first += 1;
    }
    let digits = if first == 32 {
        vec![b'0']
    } else {
        let bytes = &little_endian[..32 - first];
        let mut out = Vec::with_capacity(bytes.len() * 2);
        for (i, byte) in bytes.iter().rev().enumerate() {
            if i == 0 && byte >> 4 == 0 {
                out.push(hex_digit(byte & 0x0f));
            } else {
                out.push(hex_digit(byte >> 4));
                out.push(hex_digit(byte & 0x0f));
            }
        }
        out
    };
    let mut text = b"0x".to_vec();
    text.extend_from_slice(&digits);
    text
}

fn hex_digit(value: u8) -> u8 {
    match value {
        0..=9 => b'0' + value,
        _ => b'a' + (value - 10),
    }
}

#[cfg(test)]
mod tests {
    use super::{encode_body, ContainerMode, FourFieldAction, HyperliquidChain};

    fn unhex(text: &str) -> Vec<u8> {
        text.as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    #[test]
    fn matches_target_case_zero_byte_for_byte() {
        let actual = encode_body(
            &[0xdd, 0xb0],
            ContainerMode::Map,
            FourFieldAction {
                tag_key: "XDj,G",
                variant: "!",
                signature_chain_id: [0; 32],
                chain: HyperliquidChain::Mainnet,
                wei: 2_119_977_418_826_161,
                nonce: 199,
            },
        );
        let expected = unhex("ddb085a558446a2c47a121b07369676e6174757265436861696e4964a3307830b068797065726c6971756964436861696ea74d61696e6e6574a3776569cf0007881bb4fb21b1a56e6f6e6365ccc7");
        assert_eq!(actual, expected);
        assert_eq!(actual.len(), 78);
        // This vector is case 0 in the committed signed-action packet:
        // its target output SHA-256 is 66e40da6e6d47af0308678a7983947843f1dba6dd6c8714c7b1a4f7e26266cff.
    }

    #[test]
    fn array_mode_omits_all_field_keys_and_the_map_tag_key() {
        let actual = encode_body(
            &[],
            ContainerMode::Array,
            FourFieldAction {
                tag_key: "unused-map-key",
                variant: "!",
                signature_chain_id: [0; 32],
                chain: HyperliquidChain::Local,
                wei: 0x80,
                nonce: 0x100,
            },
        );
        assert_eq!(actual[0], 0x95);
        assert_eq!(&actual[1..3], &[0xa1, b'!']);
        assert_eq!(&actual[3..6], &[0xa3, b'0', b'x']);
        assert!(!actual.windows(4).any(|w| w == b"wei"));
        assert!(!actual.windows(5).any(|w| w == b"nonce"));
        assert!(actual.windows(3).any(|w| w == [0xcd, 0x01, 0x00]));
    }

    #[test]
    fn matches_target_case_twenty_five_array_bytes() {
        let actual = encode_body(
            &[0x26],
            ContainerMode::Array,
            FourFieldAction {
                tag_key: "unused-map-key",
                variant: ";zAT<",
                signature_chain_id: {
                    let mut value = [0; 32];
                    value[..11].copy_from_slice(&[
                        0x71, 0xfd, 0x42, 0xc6, 0x94, 0x1c, 0x40, 0xe9, 0x37, 0xa0, 0x22,
                    ]);
                    value
                },
                chain: HyperliquidChain::Testnet,
                wei: 43_375_870_315_240,
                nonce: 9_408_746_592_819_745_728,
            },
        );
        let expected = unhex("2695a53b7a41543cb8307832326130333765393430316339346336343266643731a7546573746e6574cf000027733b578ae8cf8292952d2eb013c0");
        assert_eq!(actual, expected);
        assert_eq!(actual.len(), 59);
        // Case 25 in the committed packet has this target output hash:
        // a3907d5dcd9583e867943d84037558416722f0c023621d4803e78026360975d8.
    }

    #[test]
    fn u256_hex_is_minimal_lowercase_and_zero_is_explicit() {
        let mut chain_id = [0; 32];
        chain_id[0] = 0x34;
        chain_id[1] = 0x12;
        let actual = encode_body(
            &[],
            ContainerMode::Array,
            FourFieldAction {
                tag_key: "",
                variant: "v",
                signature_chain_id: chain_id,
                chain: HyperliquidChain::Testnet,
                wei: 1,
                nonce: 1,
            },
        );
        assert!(actual.windows(6).any(|w| w == b"0x1234"));
    }
    #[test]
    fn matches_target_packet_case_300_variant_str8_boundary() {
        let actual = encode_body(
            &[0x1e],
            ContainerMode::Map,
            FourFieldAction {
                tag_key: "8uoH4N=wN^v.",
                variant: "9i,$w!U -/D8Et_eDjhVX/_CI'P\\nD:'",
                signature_chain_id: [
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ],
                chain: HyperliquidChain::Local,
                wei: 127,
                nonce: 1,
            },
        );
        let expected = unhex("1e85ac38756f48344e3d774e5e762ed92039692c24772155202d2f443845745f65446a6856582f5f434927505c6e443a27b07369676e6174757265436861696e4964b330783130303030303030303030303030303030b068797065726c6971756964436861696ea54c6f63616ca37765697fa56e6f6e636501");
        assert_eq!(actual, expected);
        assert_eq!(actual.len(), 121);
    }
}
