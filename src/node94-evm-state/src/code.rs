use crate::{
    DecodeError, EncodeError, SerializedValue,
    msgpack::{Cursor, write_array_len, write_bin, write_map_len, write_str, write_uint},
    types::{JumpTable, StoredCode},
};

const LSB0_ORDER: &str = "bitvec::order::Lsb0";

pub fn encode_code(code: &StoredCode) -> Result<SerializedValue, EncodeError> {
    let mut out = Vec::new();
    write_map_len(&mut out, 1)?;
    match code {
        StoredCode::LegacyRaw(bytecode) => {
            write_str(&mut out, "LegacyRaw")?;
            write_bin(&mut out, bytecode)?;
        }
        StoredCode::LegacyAnalyzed {
            bytecode,
            original_len,
            jump_table,
        } => {
            write_str(&mut out, "LegacyAnalyzed")?;
            write_map_len(&mut out, 3)?;
            write_str(&mut out, "bytecode")?;
            write_bin(&mut out, bytecode)?;
            write_str(&mut out, "original_len")?;
            write_uint(&mut out, *original_len);
            write_str(&mut out, "jump_table")?;
            write_jump_table(&mut out, jump_table)?;
        }
        StoredCode::Eof => return Err(EncodeError::UnsupportedVariant("Eof")),
        StoredCode::Eip7702(value) => {
            write_str(&mut out, "Eip7702")?;
            write_map_len(&mut out, 3)?;
            write_str(&mut out, "delegated_address")?;
            write_bin(&mut out, value.delegated_address.as_bytes())?;
            write_str(&mut out, "version")?;
            write_uint(&mut out, value.version);
            write_str(&mut out, "raw")?;
            write_bin(&mut out, &value.raw)?;
        }
    }
    Ok(SerializedValue::ContractCode(out))
}

fn write_jump_table(out: &mut Vec<u8>, jump_table: &JumpTable) -> Result<(), EncodeError> {
    if jump_table.head != 0 {
        return Err(EncodeError::InvalidJumpTable(
            "nonzero head writer selection is unresolved",
        ));
    }
    let byte_len = usize::try_from(jump_table.bits.div_ceil(8))
        .map_err(|_| EncodeError::LengthOverflow("jump-table bit length"))?;
    if byte_len > jump_table.data.len() {
        return Err(EncodeError::InvalidJumpTable(
            "bit count exceeds data capacity",
        ));
    }

    write_map_len(out, 4)?;
    write_str(out, "order")?;
    write_str(out, LSB0_ORDER)?;
    write_str(out, "head")?;
    write_map_len(out, 2)?;
    write_str(out, "width")?;
    write_uint(out, 8);
    write_str(out, "index")?;
    write_uint(out, u64::from(jump_table.head));
    write_str(out, "bits")?;
    write_uint(out, jump_table.bits);
    write_str(out, "data")?;
    write_array_len(out, byte_len)?;

    for (index, byte) in jump_table.data[..byte_len].iter().copied().enumerate() {
        let value = if index + 1 == byte_len && !jump_table.bits.is_multiple_of(8) {
            let mask = (1_u8 << (jump_table.bits % 8)) - 1;
            byte & mask
        } else {
            byte
        };
        write_uint(out, u64::from(value));
    }
    Ok(())
}

/// Decode the two reader branches whose payloads are sufficiently established.
///
/// The outer map-size rule and jump-table capacity/order rules are native observations.
/// Requiring writer field order is a strict implementation policy because the map-loop
/// acceptance order remains unresolved. Eof and Eip7702 readers are intentionally unsupported.
pub fn decode_supported_code(input: &[u8]) -> Result<StoredCode, DecodeError> {
    let mut cursor = Cursor::new(input);
    let len = cursor.map_len()?;
    if len != 1 {
        return Err(DecodeError::WrongContainerLength {
            context: "stored-code variant map",
            expected: 1,
            actual: len,
        });
    }
    let variant = cursor.string()?;
    let code = match variant {
        "LegacyRaw" => StoredCode::LegacyRaw(cursor.binary()?.to_vec()),
        "LegacyAnalyzed" => read_legacy_analyzed(&mut cursor)?,
        "Eof" | "Eip7702" => return Err(DecodeError::UnsupportedVariant(variant.to_owned())),
        other => return Err(DecodeError::UnsupportedVariant(other.to_owned())),
    };
    cursor.finish()?;
    Ok(code)
}

fn read_legacy_analyzed(cursor: &mut Cursor<'_>) -> Result<StoredCode, DecodeError> {
    require_container("LegacyAnalyzed map", 3, cursor.map_len()?)?;
    require_field(cursor, "bytecode")?;
    let bytecode = cursor.binary()?.to_vec();
    require_field(cursor, "original_len")?;
    let original_len = cursor.uint()?;
    require_field(cursor, "jump_table")?;
    let jump_table = read_jump_table(cursor)?;
    Ok(StoredCode::LegacyAnalyzed {
        bytecode,
        original_len,
        jump_table,
    })
}

fn read_jump_table(cursor: &mut Cursor<'_>) -> Result<JumpTable, DecodeError> {
    require_container("jump-table map", 4, cursor.map_len()?)?;
    require_field(cursor, "order")?;
    let order = cursor.string()?;
    if order != LSB0_ORDER {
        return Err(DecodeError::InvalidOrder(order.to_owned()));
    }

    require_field(cursor, "head")?;
    require_container("jump-table head map", 2, cursor.map_len()?)?;
    require_field(cursor, "width")?;
    if cursor.uint()? != 8 {
        return Err(DecodeError::InvalidJumpTable("head width must be 8"));
    }
    require_field(cursor, "index")?;
    let head = u8::try_from(cursor.uint()?).map_err(|_| DecodeError::IntegerOverflow)?;
    if head > 7 {
        return Err(DecodeError::InvalidJumpTable(
            "head index must be at most 7",
        ));
    }

    require_field(cursor, "bits")?;
    let bits = cursor.uint()?;
    require_field(cursor, "data")?;
    let data_len = cursor.array_len()?;
    let mut data = Vec::with_capacity(data_len);
    for _ in 0..data_len {
        data.push(u8::try_from(cursor.uint()?).map_err(|_| DecodeError::IntegerOverflow)?);
    }

    let capacity = (data_len as u128 * 8).saturating_sub(u128::from(head));
    if u128::from(bits) > capacity {
        return Err(DecodeError::InvalidJumpTable(
            "bit count exceeds data capacity",
        ));
    }
    if head != 0 {
        return Err(DecodeError::InvalidJumpTable(
            "nonzero head acceptance checks are unresolved",
        ));
    }
    let expected_len =
        usize::try_from(bits.div_ceil(8)).map_err(|_| DecodeError::IntegerOverflow)?;
    if expected_len != data.len() {
        return Err(DecodeError::InvalidJumpTable(
            "strict writer form requires exact data length",
        ));
    }
    if let Some(last) = data.last()
        && !bits.is_multiple_of(8)
        && (*last >> (bits % 8)) != 0
    {
        return Err(DecodeError::NonCanonical("jump-table tail bits"));
    }
    Ok(JumpTable { head, bits, data })
}

fn require_field(cursor: &mut Cursor<'_>, expected: &'static str) -> Result<(), DecodeError> {
    let actual = cursor.string()?;
    if actual == expected {
        Ok(())
    } else {
        Err(DecodeError::WrongField {
            expected,
            actual: actual.to_owned(),
        })
    }
}

fn require_container(
    context: &'static str,
    expected: usize,
    actual: usize,
) -> Result<(), DecodeError> {
    if actual == expected {
        Ok(())
    } else {
        Err(DecodeError::WrongContainerLength {
            context,
            expected,
            actual,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AccountAddress, Eip7702Code};

    #[test]
    fn target_derived_legacy_raw_example() {
        let code = StoredCode::LegacyRaw(vec![0x60, 0x01, 0x60, 0x01, 0x55]);
        let encoded = encode_code(&code).unwrap();
        assert_eq!(
            hex(encoded.as_bytes()),
            "81a94c6567616379526177c4056001600155"
        );
        assert_eq!(decode_supported_code(encoded.as_bytes()), Ok(code));
    }

    #[test]
    fn target_derived_analyzed_examples() {
        let empty = StoredCode::LegacyAnalyzed {
            bytecode: Vec::new(),
            original_len: 0,
            jump_table: JumpTable {
                head: 0,
                bits: 0,
                data: Vec::new(),
            },
        };
        let empty_encoded = encode_code(&empty).unwrap();
        assert_eq!(
            hex(empty_encoded.as_bytes()),
            "81ae4c6567616379416e616c797a656483a862797465636f6465c400ac6f726967696e616c5f6c656e00aa6a756d705f7461626c6584a56f72646572b36269747665633a3a6f726465723a3a4c736230a46865616482a5776964746808a5696e64657800a46269747300a46461746190"
        );
        assert_eq!(decode_supported_code(empty_encoded.as_bytes()), Ok(empty));

        let non_aligned = StoredCode::LegacyAnalyzed {
            bytecode: vec![0x60, 0x01, 0x60, 0x01, 0x55],
            original_len: 5,
            jump_table: JumpTable {
                head: 0,
                bits: 12,
                data: vec![0xff, 0xff],
            },
        };
        assert_eq!(
            hex(encode_code(&non_aligned).unwrap().as_bytes()),
            "81ae4c6567616379416e616c797a656483a862797465636f6465c4056001600155ac6f726967696e616c5f6c656e05aa6a756d705f7461626c6584a56f72646572b36269747665633a3a6f726465723a3a4c736230a46865616482a5776964746808a5696e64657800a4626974730ca46461746192ccff0f"
        );
    }

    #[test]
    fn target_derived_eip7702_writer_example() {
        let code = StoredCode::Eip7702(Eip7702Code {
            delegated_address: AccountAddress::new(core::array::from_fn(|index| {
                0xa0 + index as u8
            })),
            version: 0,
            raw: [vec![0xef, 0x01, 0x00], (0xa0_u8..=0xb3).collect()].concat(),
        });
        assert_eq!(
            hex(encode_code(&code).unwrap().as_bytes()),
            "81a74569703737303283b164656c6567617465645f61646472657373c414a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3a776657273696f6e00a3726177c417ef0100a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3"
        );
        assert!(matches!(
            decode_supported_code(encode_code(&code).unwrap().as_bytes()),
            Err(DecodeError::UnsupportedVariant(variant)) if variant == "Eip7702"
        ));
    }

    #[test]
    fn unsupported_and_corrupt_forms_fail_closed() {
        assert_eq!(
            encode_code(&StoredCode::Eof),
            Err(EncodeError::UnsupportedVariant("Eof"))
        );
        assert!(matches!(
            decode_supported_code(&[0x80]),
            Err(DecodeError::WrongContainerLength { actual: 0, .. })
        ));
        assert!(matches!(
            decode_supported_code(&[0xa9, b'L', b'e', b'g', b'a', b'c', b'y', b'R', b'a', b'w']),
            Err(DecodeError::InvalidMarker(0xa9))
        ));
    }

    #[test]
    fn wrong_jump_table_encoding_is_rejected() {
        let code = StoredCode::LegacyAnalyzed {
            bytecode: Vec::new(),
            original_len: 0,
            jump_table: JumpTable {
                head: 0,
                bits: 9,
                data: vec![0xff],
            },
        };
        assert!(matches!(
            encode_code(&code),
            Err(EncodeError::InvalidJumpTable(
                "bit count exceeds data capacity"
            ))
        ));

        let mut bytes = encode_code(&StoredCode::LegacyAnalyzed {
            bytecode: Vec::new(),
            original_len: 0,
            jump_table: JumpTable {
                head: 0,
                bits: 8,
                data: vec![1],
            },
        })
        .unwrap()
        .into_bytes();
        let position = find_subslice(&bytes, LSB0_ORDER.as_bytes()).unwrap();
        bytes[position] = b'X';
        assert!(matches!(
            decode_supported_code(&bytes),
            Err(DecodeError::InvalidOrder(_))
        ));
    }

    fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack
            .windows(needle.len())
            .position(|window| window == needle)
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
