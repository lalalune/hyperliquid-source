use crate::{
    DecodeError, SerializedDatabaseKey, StateKey, StateTable,
    types::{AccountAddress, CodeHash, StorageSlot},
};

const ACCOUNT_PREFIX: [u8; 2] = *b"Ea";
const CODE_PREFIX: [u8; 2] = *b"Ec";
const STORAGE_PREFIX: [u8; 2] = *b"Es";

#[must_use]
pub fn encode_key(key: &StateKey) -> SerializedDatabaseKey {
    let mut bytes = Vec::with_capacity(match key {
        StateKey::Account(_) => 22,
        StateKey::ContractCode(_) => 34,
        StateKey::Storage { .. } => 54,
    });
    match key {
        StateKey::Account(address) => {
            bytes.extend_from_slice(&ACCOUNT_PREFIX);
            bytes.extend_from_slice(address.as_bytes());
        }
        StateKey::ContractCode(hash) => {
            bytes.extend_from_slice(&CODE_PREFIX);
            bytes.extend_from_slice(hash.as_bytes());
        }
        StateKey::Storage { address, slot } => {
            bytes.extend_from_slice(&STORAGE_PREFIX);
            bytes.extend_from_slice(address.as_bytes());
            bytes.extend_from_slice(&slot.to_be_bytes());
        }
    }
    SerializedDatabaseKey::new_validated(bytes)
}

pub fn decode_key(bytes: &[u8]) -> Result<StateKey, DecodeError> {
    if bytes.len() < 2 {
        return Err(DecodeError::WrongLength {
            context: "database key prefix",
            expected: 2,
            actual: bytes.len(),
        });
    }
    let prefix = [bytes[0], bytes[1]];
    match prefix {
        ACCOUNT_PREFIX => {
            require_length("account key", 22, bytes.len())?;
            Ok(StateKey::Account(AccountAddress::try_from(&bytes[2..])?))
        }
        CODE_PREFIX => {
            require_length("contract-code key", 34, bytes.len())?;
            Ok(StateKey::ContractCode(CodeHash::try_from(&bytes[2..])?))
        }
        STORAGE_PREFIX => {
            require_length("storage key", 54, bytes.len())?;
            let address = AccountAddress::try_from(&bytes[2..22])?;
            let slot: [u8; 32] = bytes[22..54].try_into().expect("length checked");
            Ok(StateKey::Storage {
                address,
                slot: StorageSlot::from_be_bytes(slot),
            })
        }
        _ => Err(DecodeError::UnknownPrefix(prefix)),
    }
}

pub fn decode_key_for_table(bytes: &[u8], expected: StateTable) -> Result<StateKey, DecodeError> {
    if bytes.len() < 2 {
        return Err(DecodeError::WrongLength {
            context: "database key prefix",
            expected: 2,
            actual: bytes.len(),
        });
    }
    let expected_prefix = match expected {
        StateTable::Account => ACCOUNT_PREFIX,
        StateTable::ContractCode => CODE_PREFIX,
        StateTable::Storage => STORAGE_PREFIX,
    };
    let actual = [bytes[0], bytes[1]];
    if actual != expected_prefix {
        return Err(DecodeError::WrongPrefix {
            expected: expected_prefix,
            actual,
        });
    }
    decode_key(bytes)
}

fn require_length(
    context: &'static str,
    expected: usize,
    actual: usize,
) -> Result<(), DecodeError> {
    if actual == expected {
        Ok(())
    } else {
        Err(DecodeError::WrongLength {
            context,
            expected,
            actual,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_derived_key_examples() {
        let address = AccountAddress::new(core::array::from_fn(|index| 0xa0 + index as u8));
        let hash = CodeHash::new(core::array::from_fn(|index| 0x20 + index as u8));
        let native_slot = core::array::from_fn(|index| index as u8);

        assert_eq!(
            hex(&encode_key(&StateKey::Account(address)).into_bytes()),
            "4561a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3"
        );
        assert_eq!(
            hex(&encode_key(&StateKey::ContractCode(hash)).into_bytes()),
            "4563202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
        );
        assert_eq!(
            hex(&encode_key(&StateKey::Storage {
                address,
                slot: StorageSlot::from_native_le_bytes(native_slot),
            })
            .into_bytes()),
            "4573a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b31f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100"
        );
    }

    #[test]
    fn strict_lengths_and_wrong_tables_are_rejected() {
        let mut account = encode_key(&StateKey::Account(AccountAddress::new([7; 20]))).into_bytes();
        assert!(matches!(
            decode_key(&account[..21]),
            Err(DecodeError::WrongLength { .. })
        ));
        account.push(0);
        assert!(matches!(
            decode_key(&account),
            Err(DecodeError::WrongLength { .. })
        ));

        let mut wrong = vec![b'E', b'c'];
        wrong.extend_from_slice(&[0; 20]);
        assert!(matches!(
            decode_key(&wrong),
            Err(DecodeError::WrongLength {
                context: "contract-code key",
                ..
            })
        ));
        wrong[1] = b'x';
        assert_eq!(decode_key(&wrong), Err(DecodeError::UnknownPrefix(*b"Ex")));

        let code = encode_key(&StateKey::ContractCode(CodeHash::new([0; 32])));
        assert_eq!(
            decode_key_for_table(code.as_bytes(), StateTable::Account),
            Err(DecodeError::WrongPrefix {
                expected: *b"Ea",
                actual: *b"Ec",
            })
        );
    }

    #[test]
    fn keys_round_trip() {
        let cases = [
            StateKey::Account(AccountAddress::new([1; 20])),
            StateKey::ContractCode(CodeHash::new([2; 32])),
            StateKey::Storage {
                address: AccountAddress::new([3; 20]),
                slot: StorageSlot::from_be_bytes([4; 32]),
            },
        ];
        for key in cases {
            assert_eq!(decode_key(encode_key(&key).as_bytes()), Ok(key));
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
