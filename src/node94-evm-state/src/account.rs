use crate::{
    AccountRecord, DecodeError, EncodeError, SerializedValue,
    msgpack::{Cursor, write_bin, write_map_len, write_str, write_uint},
    types::{CodeHash, EMPTY_CODE_HASH},
};

pub fn encode_account(account: &AccountRecord) -> Result<SerializedValue, EncodeError> {
    let include_balance = account.balance != [0; 32];
    let include_nonce = account.nonce != 0;
    let include_code_hash = account.code_hash.into_bytes() != EMPTY_CODE_HASH;
    let fields =
        usize::from(include_balance) + usize::from(include_nonce) + usize::from(include_code_hash);

    let mut out = Vec::with_capacity(1 + fields * 36);
    write_map_len(&mut out, fields)?;
    if include_balance {
        write_str(&mut out, "b")?;
        write_bin(&mut out, &account.balance)?;
    }
    if include_nonce {
        write_str(&mut out, "n")?;
        write_uint(&mut out, account.nonce);
    }
    if include_code_hash {
        write_str(&mut out, "c")?;
        write_bin(&mut out, account.code_hash.as_bytes())?;
    }
    Ok(SerializedValue::Account(out))
}

/// Decode the canonical writer form established for node #94.
///
/// Requiring writer order and rejecting explicit defaults is this crate's strict policy;
/// the retained packet does not establish those native reader rejection rules.
pub fn decode_account(input: &[u8]) -> Result<AccountRecord, DecodeError> {
    let mut cursor = Cursor::new(input);
    let len = cursor.map_len()?;
    if len > 3 {
        return Err(DecodeError::WrongContainerLength {
            context: "account map",
            expected: 3,
            actual: len,
        });
    }

    let mut account = AccountRecord::default();
    let mut last_order = 0_u8;
    for _ in 0..len {
        let field = cursor.string()?;
        let order = match field {
            "b" => 1,
            "n" => 2,
            "c" => 3,
            actual => {
                return Err(DecodeError::WrongField {
                    expected: "b, n, or c",
                    actual: actual.to_owned(),
                });
            }
        };
        if order <= last_order {
            return Err(if order == last_order {
                DecodeError::DuplicateField(field.to_owned())
            } else {
                DecodeError::NonCanonical("account field order")
            });
        }
        last_order = order;

        match field {
            "b" => {
                let value = cursor.binary()?;
                if value.len() != 32 {
                    return Err(DecodeError::InvalidBinaryLength {
                        context: "account balance",
                        expected: 32,
                        actual: value.len(),
                    });
                }
                account.balance.copy_from_slice(value);
                if account.balance == [0; 32] {
                    return Err(DecodeError::NonCanonical("explicit zero balance"));
                }
            }
            "n" => {
                account.nonce = cursor.uint()?;
                if account.nonce == 0 {
                    return Err(DecodeError::NonCanonical("explicit zero nonce"));
                }
            }
            "c" => {
                let value = cursor.binary()?;
                if value.len() != 32 {
                    return Err(DecodeError::InvalidBinaryLength {
                        context: "account code hash",
                        expected: 32,
                        actual: value.len(),
                    });
                }
                let value: [u8; 32] = value.try_into().expect("length checked");
                if value == EMPTY_CODE_HASH {
                    return Err(DecodeError::NonCanonical("explicit empty-code hash"));
                }
                account.code_hash = CodeHash::new(value);
            }
            _ => unreachable!("field matched above"),
        }
    }
    cursor.finish()?;
    Ok(account)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_examples_are_exact() {
        assert_eq!(
            encode_account(&AccountRecord::default())
                .unwrap()
                .as_bytes(),
            &[0x80]
        );

        let account = AccountRecord {
            nonce: 5,
            ..AccountRecord::default()
        };
        assert_eq!(
            encode_account(&account).unwrap().as_bytes(),
            &[0x81, 0xa1, b'n', 0x05]
        );
        assert_eq!(decode_account(&[0x81, 0xa1, b'n', 0x05]), Ok(account));
    }

    #[test]
    fn all_fields_use_observed_order_and_binary_values() {
        let account = AccountRecord {
            balance: [0x11; 32],
            nonce: 0x100,
            code_hash: CodeHash::new([0x22; 32]),
        };
        let encoded = encode_account(&account).unwrap();
        let bytes = encoded.as_bytes();
        assert_eq!(bytes[0], 0x83);
        assert_eq!(&bytes[1..4], &[0xa1, b'b', 0xc4]);
        assert_eq!(&bytes[37..40], &[0xa1, b'n', 0xcd]);
        assert_eq!(&bytes[42..45], &[0xa1, b'c', 0xc4]);
        assert_eq!(decode_account(bytes), Ok(account));
    }

    #[test]
    fn strict_policy_rejects_mutations_and_changed_omission() {
        assert!(matches!(
            decode_account(&[0x81, 0xa1, b'n']),
            Err(DecodeError::UnexpectedEof)
        ));
        assert!(matches!(
            decode_account(&[0x91]),
            Err(DecodeError::InvalidMarker(0x91))
        ));
        assert!(matches!(
            decode_account(&[0x81, 0xa1, b'n', 0x00]),
            Err(DecodeError::NonCanonical("explicit zero nonce"))
        ));

        let mut swapped = vec![0x82, 0xa1, b'n', 1, 0xa1, b'b', 0xc4, 32];
        swapped.extend_from_slice(&[1; 32]);
        assert!(matches!(
            decode_account(&swapped),
            Err(DecodeError::NonCanonical("account field order"))
        ));
    }
}
