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
    #[test]
    fn matches_target_packet_case_100_messagepack_string_boundary() {
        let amount = unhex("2dd5f971f9e6c57ca5f0eecc7f31e114155a5c9001d77feb6e70cc7a3fd2420b2819b3966c03b3a261f835b92d396f997add41204082797af93439e009703a64623fabda4a3355a461e64a21447d91c0182083509a901c36fd7f58ced904ba5b6f4827e61741c1d941715bcdb169074033a08edbbb2bab114040eb7d34cc972c2129098bcb398d73fdabed07bd893a104c8602c790107ca94d1dfafd8f6322dcf7d6bb084ff06ec4d36be43838c50a3565f7374c92d66f8b4e961e6642ecd78b7891cf0a4f0cf2e10f6c5f2838e3320d035574d02af3bbfe84651adcf17b0ea115131da0486dc6a51d1add8b2cee82563b9f24dd4729cb4080e08bacae32cafd");
        let actual = encode_body(
            &[0x46, 0x9e],
            ContainerMode::Map,
            UsdClassTransferAction {
                tag_key: "0",
                variant: "vO\"9>",
                signature_chain_id: [
                    0x86, 0xf3, 0x70, 0xa0, 0x3d, 0xa3, 0x5f, 0xe1, 0xc1, 0xd1, 0x3c, 0x1a, 0xfe,
                    0xf7, 0x54, 0x6f, 0x0f, 0x5b, 0x36, 0x3b, 0xd7, 0xd6, 0x32, 0xf5, 0xcb, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ],
                chain: HyperliquidChain::Sandbox,
                amount: &amount,
                to_perp: false,
                nonce: 41833,
            },
        );
        let expected = unhex("469e86a130a5764f22393eb07369676e6174757265436861696e4964d93430786362663533326436643733623336356230663666353466376665316133636431633165313566613333646130373066333836b068797065726c6971756964436861696ea753616e64626f78a6616d6f756e74da01002dd5f971f9e6c57ca5f0eecc7f31e114155a5c9001d77feb6e70cc7a3fd2420b2819b3966c03b3a261f835b92d396f997add41204082797af93439e009703a64623fabda4a3355a461e64a21447d91c0182083509a901c36fd7f58ced904ba5b6f4827e61741c1d941715bcdb169074033a08edbbb2bab114040eb7d34cc972c2129098bcb398d73fdabed07bd893a104c8602c790107ca94d1dfafd8f6322dcf7d6bb084ff06ec4d36be43838c50a3565f7374c92d66f8b4e961e6642ecd78b7891cf0a4f0cf2e10f6c5f2838e3320d035574d02af3bbfe84651adcf17b0ea115131da0486dc6a51d1add8b2cee82563b9f24dd4729cb4080e08bacae32cafda6746f50657270c2a56e6f6e6365cda369");
        assert_eq!(actual, expected);
        assert_eq!(actual.len(), 390);
    }
    #[test]
    fn matches_target_packet_case_300_messagepack_string_boundary() {
        let amount = unhex("66472102c0b1f81ab073618ec484898192c2c13b6f05c4957e471a23fdf9d68111dd19ecbb6d769ab8df41f4e20704516dc94fc612a52d8c76c9e06e0ccf50f879bc7a0e1f8ad106d6ed89102286e6ee06c5117c693fd489f23c079ac5b0300b569b055436897e5ed3f9745848433c505f960a212bd85cd8be93743166c69fe445218eb63608e86af7de0be7245c245a38e18c7a5824402205b15e8a0b67bdeeeef571ac22deabf5857897c5812554d1d207a5009a26ab6c47f0c5c1e135bad48c292ac25e2f3d5be637d23f5e0cf7903bc91c0273691a98cf1897d6fe4f7cc7d28c16e5a27608f831c13ff64a321382848054f9520a89fdb0a84f97b4c8b3");
        let actual = encode_body(
            &[],
            ContainerMode::Map,
            UsdClassTransferAction {
                tag_key: "1+NQ_QE",
                variant: "]$Nl6YSL",
                signature_chain_id: [
                    0xbf, 0x54, 0xdb, 0xa5, 0x4c, 0x59, 0x2d, 0xe9, 0x76, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ],
                chain: HyperliquidChain::Mainnet,
                amount: &amount,
                to_perp: true,
                nonce: 2383902,
            },
        );
        let expected = unhex("86a7312b4e515f5145a85d244e6c3659534cb07369676e6174757265436861696e4964b43078373665393264353934636135646235346266b068797065726c6971756964436861696ea74d61696e6e6574a6616d6f756e74d9ff66472102c0b1f81ab073618ec484898192c2c13b6f05c4957e471a23fdf9d68111dd19ecbb6d769ab8df41f4e20704516dc94fc612a52d8c76c9e06e0ccf50f879bc7a0e1f8ad106d6ed89102286e6ee06c5117c693fd489f23c079ac5b0300b569b055436897e5ed3f9745848433c505f960a212bd85cd8be93743166c69fe445218eb63608e86af7de0be7245c245a38e18c7a5824402205b15e8a0b67bdeeeef571ac22deabf5857897c5812554d1d207a5009a26ab6c47f0c5c1e135bad48c292ac25e2f3d5be637d23f5e0cf7903bc91c0273691a98cf1897d6fe4f7cc7d28c16e5a27608f831c13ff64a321382848054f9520a89fdb0a84f97b4c8b3a6746f50657270c3a56e6f6e6365ce0024601e");
        assert_eq!(actual, expected);
        assert_eq!(actual.len(), 364);
    }
}
