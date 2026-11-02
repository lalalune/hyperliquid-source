use node94_evm_state::{
    AccountAddress, AccountRecord, CodeHash, DecodeError, JumpTable, StateKey, StateTable,
    StorageSlot, StorageValue, StoredCode, decode_account, decode_key_for_table,
    decode_storage_value, encode_account, encode_code, encode_key, encode_storage_value,
};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn retained_key_fixtures_match_byte_for_byte() {
    let address = AccountAddress::new(core::array::from_fn(|index| 0xa0 + index as u8));
    let code_hash = CodeHash::new(core::array::from_fn(|index| 0x20 + index as u8));
    assert_eq!(
        hex(encode_key(&StateKey::Account(address)).as_bytes()),
        "4561a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3"
    );
    assert_eq!(
        hex(encode_key(&StateKey::ContractCode(code_hash)).as_bytes()),
        "4563202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
    );
    assert_eq!(
        hex(encode_key(&StateKey::Storage {
            address,
            slot: StorageSlot::from_native_le_bytes(core::array::from_fn(|index| index as u8)),
        })
        .as_bytes()),
        "4573a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b31f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100"
    );
}

#[test]
fn retained_account_fixtures_match_byte_for_byte() {
    assert_eq!(
        encode_account(&AccountRecord::default())
            .unwrap()
            .as_bytes(),
        [0x80]
    );
    let nonce_five = AccountRecord {
        nonce: 5,
        ..AccountRecord::default()
    };
    assert_eq!(
        encode_account(&nonce_five).unwrap().as_bytes(),
        [0x81, 0xa1, b'n', 0x05]
    );
    assert_eq!(decode_account(&[0x81, 0xa1, b'n', 0x05]), Ok(nonce_five));
}

#[test]
fn retained_code_fixtures_match_byte_for_byte() {
    let raw = StoredCode::LegacyRaw(vec![0x60, 0x01, 0x60, 0x01, 0x55]);
    assert_eq!(
        hex(encode_code(&raw).unwrap().as_bytes()),
        "81a94c6567616379526177c4056001600155"
    );

    let analyzed = StoredCode::LegacyAnalyzed {
        bytecode: vec![0x60, 0x01, 0x60, 0x01, 0x55],
        original_len: 5,
        jump_table: JumpTable {
            head: 0,
            bits: 12,
            data: vec![0xff, 0xff],
        },
    };
    assert_eq!(
        hex(encode_code(&analyzed).unwrap().as_bytes()),
        "81ae4c6567616379416e616c797a656483a862797465636f6465c4056001600155ac6f726967696e616c5f6c656e05aa6a756d705f7461626c6584a56f72646572b36269747665633a3a6f726465723a3a4c736230a46865616482a5776964746808a5696e64657800a4626974730ca46461746192ccff0f"
    );
}

#[test]
fn corruption_controls_reject_wrong_table_marker_length_and_endian() {
    let code_key = encode_key(&StateKey::ContractCode(CodeHash::new([7; 32])));
    assert!(matches!(
        decode_key_for_table(code_key.as_bytes(), StateTable::Account),
        Err(DecodeError::WrongPrefix { .. })
    ));
    assert!(matches!(
        decode_account(&[0x91]),
        Err(DecodeError::InvalidMarker(0x91))
    ));
    assert!(decode_storage_value(&[0; 31]).is_err());

    let native = core::array::from_fn(|index| index as u8);
    let encoded = encode_storage_value(StorageValue::from_native_le_bytes(native));
    assert_eq!(
        encoded.as_bytes(),
        native.iter().rev().copied().collect::<Vec<_>>()
    );
    assert_ne!(encoded.as_bytes(), native);
}
