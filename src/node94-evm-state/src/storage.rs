use crate::{DecodeError, SerializedValue, StorageValue};

#[must_use]
pub fn encode_storage_value(value: StorageValue) -> SerializedValue {
    SerializedValue::Storage(value.to_be_bytes())
}

pub fn decode_storage_value(input: &[u8]) -> Result<StorageValue, DecodeError> {
    let actual = input.len();
    let bytes = input.try_into().map_err(|_| DecodeError::WrongLength {
        context: "storage value",
        expected: 32,
        actual,
    })?;
    Ok(StorageValue::from_be_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boundary_values_are_exact() {
        let mut cases = vec![[0; 32], [0xff; 32]];
        let mut one = [0; 32];
        one[31] = 1;
        cases.push(one);
        let mut high = [0; 32];
        high[0] = 0x80;
        cases.push(high);
        let mut low = [0; 32];
        low[31] = 0x01;
        cases.push(low);
        cases.push(core::array::from_fn(|index| {
            if index % 2 == 0 { 0xaa } else { 0x55 }
        }));

        for bytes in cases {
            let value = StorageValue::from_be_bytes(bytes);
            assert_eq!(encode_storage_value(value).as_bytes(), bytes);
            assert_eq!(decode_storage_value(&bytes), Ok(value));
        }
    }

    #[test]
    fn every_native_boundary_byte_is_reversed() {
        for index in 0..32 {
            let mut native = [0; 32];
            native[index] = 0x80 | index as u8;
            let encoded = encode_storage_value(StorageValue::from_native_le_bytes(native));
            assert_eq!(encoded.as_bytes()[31 - index], 0x80 | index as u8);
            assert_eq!(
                encoded.as_bytes().iter().filter(|byte| **byte != 0).count(),
                1
            );
        }
    }

    #[test]
    fn incorrect_endianness_control_differs() {
        let native = core::array::from_fn(|index| index as u8);
        let encoded = encode_storage_value(StorageValue::from_native_le_bytes(native));
        assert_eq!(
            encoded.as_bytes(),
            &native.iter().rev().copied().collect::<Vec<_>>()
        );
        assert_ne!(encoded.as_bytes(), native);
    }

    #[test]
    fn truncated_and_extended_values_are_rejected() {
        assert!(matches!(
            decode_storage_value(&[0; 31]),
            Err(DecodeError::WrongLength { .. })
        ));
        assert!(matches!(
            decode_storage_value(&[0; 33]),
            Err(DecodeError::WrongLength { .. })
        ));
    }
}
