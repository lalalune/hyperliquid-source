//! Value model of node #115's observed five-field outcome record writer.
#![forbid(unsafe_code)]

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CopyFamily {
    Family226,
    Family419,
    Family52f,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutcomeRecord<'a> {
    pub outcome: u64,
    pub settle_fraction: &'a str,
    pub details: &'a str,
    pub name: &'a str,
    pub description: &'a str,
    pub side_one: &'a str,
    pub side_two: &'a str,
}

/// Host-side limitation for inputs outside the packet's exercised string range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EncodeError {
    StringAtLeast65536Bytes,
}

/// Encodes one record's bytes, excluding the surrounding B-tree-set array.
///
/// `struct_flag` is the byte at serializer record offset `+0x1b`; `side_flag`
/// is the byte at `+0x1c`. The target packets exercise structural flags 0, 1,
/// and 2, and several side flags. The value encoder deliberately does not
/// model reserve/grow calls, allocation failures, or the outer set iterator.
pub fn encode_record(
    record: OutcomeRecord<'_>,
    family: CopyFamily,
    struct_flag: u8,
    side_flag: u8,
) -> Result<Vec<u8>, EncodeError> {
    let strings = [
        record.settle_fraction,
        record.details,
        record.name,
        record.description,
        record.side_one,
        record.side_two,
    ];
    if strings.iter().any(|value| value.len() >= 65_536) {
        return Err(EncodeError::StringAtLeast65536Bytes);
    }

    let named = struct_flag == 1;
    let mut output = Vec::new();
    output.push((struct_flag ^ 1).wrapping_shl(4) | 0x85);

    if named {
        write_str(&mut output, "outcome");
    }
    write_uint(&mut output, record.outcome);

    if named {
        write_str(&mut output, "settleFraction");
    }
    write_str(&mut output, record.settle_fraction);

    if named {
        write_str(&mut output, "details");
    }
    write_str(&mut output, record.details);

    let name_key = match family {
        CopyFamily::Family226 | CopyFamily::Family419 => named,
        CopyFamily::Family52f => struct_flag != 0,
    };
    if name_key {
        write_str(&mut output, "nameAndDescription");
    }
    output.push(0x92);
    write_str(&mut output, record.name);
    write_str(&mut output, record.description);

    if named {
        write_str(&mut output, "sideNames");
    }
    // The native helper and generic array-header paths both emit 0x92 here.
    let _uses_header_writer = side_flag == 2;
    output.push(0x92);
    write_str(&mut output, record.side_one);
    write_str(&mut output, record.side_two);

    Ok(output)
}

fn write_uint(output: &mut Vec<u8>, value: u64) {
    match value {
        0..=0x7f => output.push(value as u8),
        0x80..=0xff => output.extend_from_slice(&[0xcc, value as u8]),
        0x100..=0xffff => {
            output.push(0xcd);
            output.extend_from_slice(&(value as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            output.push(0xce);
            output.extend_from_slice(&(value as u32).to_be_bytes());
        }
        _ => {
            output.push(0xcf);
            output.extend_from_slice(&value.to_be_bytes());
        }
    }
}

fn write_str(output: &mut Vec<u8>, value: &str) {
    let bytes = value.as_bytes();
    match bytes.len() {
        0..=31 => output.push(0xa0 | bytes.len() as u8),
        32..=255 => output.extend_from_slice(&[0xd9, bytes.len() as u8]),
        _ => {
            output.push(0xda);
            output.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
        }
    }
    output.extend_from_slice(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> OutcomeRecord<'static> {
        OutcomeRecord {
            outcome: 1,
            settle_fraction: "s",
            details: "",
            name: "n",
            description: "d",
            side_one: "l",
            side_two: "r",
        }
    }

    #[test]
    fn compact_mode_emits_array_header_and_five_values_in_order() {
        let bytes = encode_record(record(), CopyFamily::Family226, 0, 0).unwrap();
        assert_eq!(
            bytes,
            [
                0x95, 0x01, 0xa1, b's', 0xa0, 0x92, 0xa1, b'n', 0xa1, b'd', 0x92, 0xa1, b'l', 0xa1,
                b'r',
            ]
        );
    }

    #[test]
    fn named_mode_emits_map_keys_in_target_order() {
        let bytes = encode_record(record(), CopyFamily::Family226, 1, 2).unwrap();
        let text = String::from_utf8_lossy(&bytes);
        let keys = [
            "outcome",
            "settleFraction",
            "details",
            "nameAndDescription",
            "sideNames",
        ];
        let positions: Vec<_> = keys.iter().map(|key| text.find(key).unwrap()).collect();
        assert!(positions.windows(2).all(|pair| pair[0] < pair[1]));
        assert_eq!(bytes[0], 0x85);
        assert_eq!(bytes.iter().filter(|byte| **byte == 0x92).count(), 2);
    }

    #[test]
    fn family_52f_uses_nonzero_rule_for_name_key() {
        let bytes = encode_record(record(), CopyFamily::Family52f, 2, 0).unwrap();
        assert!(
            bytes
                .windows(b"nameAndDescription".len())
                .any(|w| w == b"nameAndDescription")
        );
        assert!(
            !bytes
                .windows(b"settleFraction".len())
                .any(|w| w == b"settleFraction")
        );
        assert_eq!(bytes[0], 0xb5);

        let sibling = encode_record(record(), CopyFamily::Family226, 2, 0).unwrap();
        assert!(
            !sibling
                .windows(b"nameAndDescription".len())
                .any(|w| w == b"nameAndDescription")
        );
    }

    #[test]
    fn unsigned_integer_and_string_width_boundaries() {
        assert_eq!(
            encode_record(
                OutcomeRecord {
                    outcome: 127,
                    ..record()
                },
                CopyFamily::Family226,
                0,
                0
            )
            .unwrap()[1],
            127
        );
        assert_eq!(
            encode_record(
                OutcomeRecord {
                    outcome: 128,
                    ..record()
                },
                CopyFamily::Family226,
                0,
                0
            )
            .unwrap()[1..3],
            [0xcc, 128]
        );
        let long = "x".repeat(32);
        let encoded = encode_record(
            OutcomeRecord {
                details: &long,
                ..record()
            },
            CopyFamily::Family226,
            0,
            0,
        )
        .unwrap();
        assert!(encoded.windows(2).any(|w| w == [0xd9, 32]));
        let too_long = "x".repeat(65_536);
        assert_eq!(
            encode_record(
                OutcomeRecord {
                    details: &too_long,
                    ..record()
                },
                CopyFamily::Family226,
                0,
                0
            ),
            Err(EncodeError::StringAtLeast65536Bytes)
        );
    }
}
