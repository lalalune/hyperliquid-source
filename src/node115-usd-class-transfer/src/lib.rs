//! Encoder for the node #115 signed-action body at VA 0x240ad50.

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
pub struct UsdClassTransferAction<'a> {
    pub tag_key: &'a str,
    pub variant: &'a str,
    /// The target stores this U256 little-endian in the action struct.
    pub signature_chain_id: [u8; 32],
    pub chain: HyperliquidChain,
    pub amount: &'a [u8],
    pub to_perp: bool,
    pub nonce: u64,
}

/// Encode the complete body, preserving a prefix already written by the caller.
pub fn encode_body(
    prefix: &[u8],
    mode: ContainerMode,
    action: UsdClassTransferAction<'_>,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(prefix.len() + action.amount.len() + 96);
    out.extend_from_slice(prefix);
    match mode {
        ContainerMode::Map => out.push(0x86),
        ContainerMode::Array => out.push(0x96),
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
    field_str(&mut out, mode, "amount", action.amount);
    field_bool(&mut out, mode, "toPerp", action.to_perp);
    field_u64(&mut out, mode, "nonce", action.nonce);
    out
}

fn field_str(out: &mut Vec<u8>, mode: ContainerMode, key: &str, value: &[u8]) {
    if mode == ContainerMode::Map {
        write_str(out, key.as_bytes());
    }
    write_str(out, value);
}

fn field_bool(out: &mut Vec<u8>, mode: ContainerMode, key: &str, value: bool) {
    if mode == ContainerMode::Map {
        write_str(out, key.as_bytes());
    }
    out.push(if value { 0xc3 } else { 0xc2 });
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
    use super::{encode_body, ContainerMode, HyperliquidChain, UsdClassTransferAction};

    fn unhex(text: &str) -> Vec<u8> {
        text.as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    #[test]
    fn matches_target_packet_case_zero_map_body() {
        let actual = encode_body(
            &[0xd9, 0x1b, 0xf1],
            ContainerMode::Map,
            UsdClassTransferAction {
                tag_key: "khj,6",
                variant: "nvV|p",
                signature_chain_id: [0; 32],
                chain: HyperliquidChain::Sandbox,
                amount: &[
                    0xe6, 0x68, 0x3a, 0xfe, 0xe5, 0x8c, 0x2f, 0xfa, 0xd7, 0xcf, 0x5e, 0x5f, 0x93,
                    0xbd, 0xd5, 0x47, 0xe3, 0xed, 0x69, 0x7d, 0x91, 0x61, 0xee, 0xd3, 0xb3, 0x8f,
                    0x5d, 0x81, 0xdc, 0x99, 0xf7, 0x46, 0x13, 0x4a, 0x0a, 0x3f, 0x46, 0x16, 0x39,
                    0x0e, 0x26, 0xd9, 0xa4,
                ],
                to_perp: true,
                nonce: 0,
            },
        );
        let expected = unhex("d91bf186a56b686a2c36a56e76567c70b07369676e6174757265436861696e4964a3307830b068797065726c6971756964436861696ea753616e64626f78a6616d6f756e74d92be6683afee58c2ffad7cf5e5f93bdd547e3ed697d9161eed3b38f5d81dc99f746134a0a3f4616390e26d9a4a6746f50657270c3a56e6f6e636500");
        assert_eq!(actual, expected);
        assert_eq!(actual.len(), 129);
    }

    #[test]
    fn matches_target_packet_case_twenty_five_array_body() {
        let mut signature_chain_id = [0; 32];
        signature_chain_id[23] = 0x08;
        let amount = unhex("64320526e9822bb3b6e74349a500cbfd90315ff66c6732e0043ff713e8651ddfa5e2bb97c0b57c0116c5008774bdc0fcd44ce82e01ecd9397b6589a2af860a2d6b761ea25694c501c6a97ab9bc7972c9c5c1d89a163611c13f2afbf8b1b33016993939bd92ee3ac02bb56932943b5bc73ed48477105d2c6daf8f4722cbb658014a85deba2bd64bdf0100c104298831332b7028ce77fbfda5031473fde8c6fc016cd9ce2c71449ce14f33a4f5643bb1682d502c4f627358d7a12fa13797449f20d5134cb7fb757bba2f085b8008a66e96f6016af6815dd724fbe3d59a27589d611656f18f101dc80b71da3302035598c45d2a577538afc016672e9e492edca8f08d6b1439a30e9de642b219cc1c6916669eb853ac95d10a989be6a5ba5bae1bab9573a55d26381ee1da9b0449");
        let actual = encode_body(
            &[0x79, 0xc4, 0xb7],
            ContainerMode::Array,
            UsdClassTransferAction {
                tag_key: "unused-map-tag",
                variant: "?*v=GWOIYb.Q_nZ9",
                signature_chain_id,
                chain: HyperliquidChain::Testnet,
                amount: &amount,
                to_perp: false,
                nonce: 0,
            },
        );
        let expected = unhex("79c4b796b03f2a763d47574f4959622e515f6e5a39d93130783830303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030a7546573746e6574da012c64320526e9822bb3b6e74349a500cbfd90315ff66c6732e0043ff713e8651ddfa5e2bb97c0b57c0116c5008774bdc0fcd44ce82e01ecd9397b6589a2af860a2d6b761ea25694c501c6a97ab9bc7972c9c5c1d89a163611c13f2afbf8b1b33016993939bd92ee3ac02bb56932943b5bc73ed48477105d2c6daf8f4722cbb658014a85deba2bd64bdf0100c104298831332b7028ce77fbfda5031473fde8c6fc016cd9ce2c71449ce14f33a4f5643bb1682d502c4f627358d7a12fa13797449f20d5134cb7fb757bba2f085b8008a66e96f6016af6815dd724fbe3d59a27589d611656f18f101dc80b71da3302035598c45d2a577538afc016672e9e492edca8f08d6b1439a30e9de642b219cc1c6916669eb853ac95d10a989be6a5ba5bae1bab9573a55d26381ee1da9b0449c200");
        assert_eq!(actual, expected);
        assert_eq!(actual.len(), 385);
    }
}
