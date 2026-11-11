//! Value-level model of the node #115 margin-mode `Content` identifier readers.
//!
//! Evidence: `research/work-items/RE-007-margin-mode-identifier-115`, target
//! SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

use std::borrow::Cow;

/// Selected body family determines the observed static variant-pool pointer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Family {
    First,
    Second,
    Third,
}

impl Family {
    fn variant_pool(self) -> u64 {
        match self {
            Self::First => 0x643e188,
            Self::Second => 0x6475de0,
            Self::Third => 0x64b7d28,
        }
    }
}

/// Logical identifier Content arms observed in the five selected bodies.
/// Text and byte payloads are supplied as borrowed slices; owned arms also
/// carry the observed capacity word used by the conditional free path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Identifier<'a> {
    U8(u8),
    U64(u64),
    String { bytes: &'a [u8], capacity: usize },
    Str(&'a [u8]),
    ByteBuf { bytes: &'a [u8], capacity: usize },
    Bytes(&'a [u8]),
    Other(u8),
}

impl Identifier<'_> {
    fn tag(self) -> u8 {
        match self {
            Self::U8(_) => 1,
            Self::U64(_) => 4,
            Self::String { .. } => 12,
            Self::Str(_) => 13,
            Self::ByteBuf { .. } => 14,
            Self::Bytes(_) => 15,
            Self::Other(tag) => tag,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DecodeError {
    InvalidValue {
        value: u64,
    },
    UnknownVariant {
        value: Vec<u8>,
        pool: u64,
        count: u64,
    },
    InvalidType {
        tag: u8,
        pool: u64,
    },
}

/// Selected ownership/helper events, represented without native pointers or ABI.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Event {
    InvalidValue {
        value: u64,
    },
    LossyBytes {
        input: Vec<u8>,
    },
    UnknownVariant {
        value: Vec<u8>,
        pool: u64,
        count: u64,
    },
    InvalidType {
        tag: u8,
        pool: u64,
    },
    FreeConvertedText {
        length: usize,
    },
    FreeIdentifier {
        tag: u8,
        capacity: usize,
    },
    DropIdentifier {
        tag: u8,
    },
    DropValue {
        tag: u8,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Outcome {
    pub result: Result<u8, DecodeError>,
    /// The original value Content is returned byte-for-byte on success.
    pub value: Option<[u8; 32]>,
    pub events: Vec<Event>,
}

const NAMES: [&[u8]; 3] = [b"normal", b"noCross", b"strictIsolated"];
const NO_VALUE_TAG: u8 = 0x16;

fn classify(bytes: &[u8]) -> Option<u8> {
    NAMES
        .iter()
        .position(|name| *name == bytes)
        .map(|index| index as u8)
}

fn append_unknown(bytes: &[u8], pool: u64, events: &mut Vec<Event>) -> DecodeError {
    let error = DecodeError::UnknownVariant {
        value: bytes.to_vec(),
        pool,
        count: 3,
    };
    events.push(Event::UnknownVariant {
        value: bytes.to_vec(),
        pool,
        count: 3,
    });
    error
}

fn visit_bytes(bytes: &[u8], pool: u64, events: &mut Vec<Event>) -> Result<u8, DecodeError> {
    let shown: Cow<'_, str> = String::from_utf8_lossy(bytes);
    events.push(Event::LossyBytes {
        input: bytes.to_vec(),
    });
    if let Some(index) = classify(bytes) {
        return Ok(index);
    }
    let error = append_unknown(shown.as_bytes(), pool, events);
    if matches!(shown, Cow::Owned(_)) {
        events.push(Event::FreeConvertedText {
            length: shown.len(),
        });
    }
    Err(error)
}

/// Decode an identifier Content and preserve the paired value Content on success.
///
/// Integer arms accept only values 0..=2. Text compares the complete byte slice
/// against the three names. ByteBuf/Bytes use lossy UTF-8 conversion before an
/// unknown-variant result. `value_tag` is the paired value's observed Content
/// tag; `value_content` is copied unchanged into successful results.
pub fn decode_identifier(
    identifier: Identifier<'_>,
    value_tag: u8,
    value_content: [u8; 32],
    family: Family,
) -> Outcome {
    let pool = family.variant_pool();
    let tag = identifier.tag();
    let mut events = Vec::new();
    let result = match identifier {
        Identifier::U8(value) => {
            let result = if value <= 2 {
                Ok(value)
            } else {
                events.push(Event::InvalidValue {
                    value: u64::from(value),
                });
                Err(DecodeError::InvalidValue {
                    value: u64::from(value),
                })
            };
            events.push(Event::DropIdentifier { tag });
            result
        }
        Identifier::U64(value) => {
            let result = if value <= 2 {
                Ok(value as u8)
            } else {
                events.push(Event::InvalidValue { value });
                Err(DecodeError::InvalidValue { value })
            };
            events.push(Event::DropIdentifier { tag });
            result
        }
        Identifier::String { bytes, capacity } => {
            let result = classify(bytes).ok_or_else(|| append_unknown(bytes, pool, &mut events));
            if capacity != 0 {
                events.push(Event::FreeIdentifier { tag, capacity });
            }
            result
        }
        Identifier::Str(bytes) => {
            let result = classify(bytes).ok_or_else(|| append_unknown(bytes, pool, &mut events));
            events.push(Event::DropIdentifier { tag });
            result
        }
        Identifier::ByteBuf { bytes, capacity } => {
            let result = visit_bytes(bytes, pool, &mut events);
            if capacity != 0 {
                events.push(Event::FreeIdentifier { tag, capacity });
            }
            result
        }
        Identifier::Bytes(bytes) => {
            let result = visit_bytes(bytes, pool, &mut events);
            events.push(Event::DropIdentifier { tag });
            result
        }
        Identifier::Other(other_tag) => {
            events.push(Event::InvalidType {
                tag: other_tag,
                pool,
            });
            Err(DecodeError::InvalidType {
                tag: other_tag,
                pool,
            })
        }
    };

    let value = if result.is_ok() {
        Some(value_content)
    } else {
        if value_tag != NO_VALUE_TAG {
            events.push(Event::DropValue { tag: value_tag });
        }
        None
    };
    Outcome {
        result,
        value,
        events,
    }
}

#[cfg(test)]
mod tests {
    use super::{decode_identifier, DecodeError, Event, Family, Identifier};

    const VALUE: [u8; 32] = [0x5a; 32];

    #[test]
    fn decodes_three_names_and_preserves_value_for_all_families() {
        let families = [Family::First, Family::Second, Family::Third];
        let names = [
            (b"normal".as_slice(), 0),
            (b"noCross".as_slice(), 1),
            (b"strictIsolated".as_slice(), 2),
        ];
        for family in families {
            for (name, expected) in names {
                let borrowed = decode_identifier(Identifier::Str(name), 4, VALUE, family);
                assert_eq!(borrowed.result, Ok(expected));
                assert_eq!(borrowed.value, Some(VALUE));
                assert_eq!(borrowed.events, [Event::DropIdentifier { tag: 13 }]);

                let owned = decode_identifier(
                    Identifier::String {
                        bytes: name,
                        capacity: name.len() + 8,
                    },
                    4,
                    VALUE,
                    family,
                );
                assert_eq!(owned.result, Ok(expected));
                assert_eq!(owned.value, Some(VALUE));
                assert_eq!(
                    owned.events,
                    [Event::FreeIdentifier {
                        tag: 12,
                        capacity: name.len() + 8
                    }]
                );
            }
        }
    }

    #[test]
    fn accepts_only_integer_indices_zero_through_two() {
        for family in [Family::First, Family::Second, Family::Third] {
            for value in 0..=2 {
                let byte = decode_identifier(Identifier::U8(value), 3, VALUE, family);
                assert_eq!(byte.result, Ok(value));
                assert_eq!(byte.value, Some(VALUE));
                let wide = decode_identifier(Identifier::U64(u64::from(value)), 3, VALUE, family);
                assert_eq!(wide.result, Ok(value));
                assert_eq!(wide.value, Some(VALUE));
            }
            let invalid = decode_identifier(Identifier::U64(u64::MAX), 3, VALUE, family);
            assert_eq!(
                invalid.result,
                Err(DecodeError::InvalidValue { value: u64::MAX })
            );
            assert_eq!(invalid.value, None);
            assert!(matches!(
                invalid.events[0],
                Event::InvalidValue { value: u64::MAX }
            ));
            assert!(invalid.events.contains(&Event::DropIdentifier { tag: 4 }));
            assert!(invalid.events.contains(&Event::DropValue { tag: 3 }));
        }
    }

    #[test]
    fn byte_visitors_apply_lossy_utf8_and_preserve_event_order() {
        let borrowed = decode_identifier(
            Identifier::Bytes(b"strictIsolated"),
            0x16,
            VALUE,
            Family::Second,
        );
        assert_eq!(borrowed.result, Ok(2));
        assert_eq!(borrowed.value, Some(VALUE));
        assert_eq!(
            borrowed.events,
            [
                Event::LossyBytes {
                    input: b"strictIsolated".to_vec()
                },
                Event::DropIdentifier { tag: 15 }
            ]
        );

        let invalid = decode_identifier(
            Identifier::ByteBuf {
                bytes: b"noC\xff",
                capacity: 16,
            },
            7,
            VALUE,
            Family::Second,
        );
        let pool = 0x6475de0;
        assert_eq!(
            invalid.result,
            Err(DecodeError::UnknownVariant {
                value: "noC�".as_bytes().to_vec(),
                pool,
                count: 3
            })
        );
        assert_eq!(invalid.value, None);
        assert_eq!(
            invalid.events,
            [
                Event::LossyBytes {
                    input: b"noC\xff".to_vec()
                },
                Event::UnknownVariant {
                    value: "noC�".as_bytes().to_vec(),
                    pool,
                    count: 3
                },
                Event::FreeConvertedText { length: 6 },
                Event::FreeIdentifier {
                    tag: 14,
                    capacity: 16
                },
                Event::DropValue { tag: 7 },
            ]
        );
    }

    #[test]
    fn exact_name_matching_and_niche_drop_rules() {
        for input in [
            b"Normal".as_slice(),
            b"normalx",
            b"noCross\0",
            b"strictIsolater",
        ] {
            let out = decode_identifier(Identifier::Str(input), 0x16, VALUE, Family::First);
            assert!(matches!(
                out.result,
                Err(DecodeError::UnknownVariant { .. })
            ));
            assert!(out.events.contains(&Event::DropIdentifier { tag: 13 }));
            assert!(!out
                .events
                .iter()
                .any(|event| matches!(event, Event::DropValue { .. })));
        }
        let other = decode_identifier(Identifier::Other(2), 15, VALUE, Family::Third);
        assert_eq!(
            other.result,
            Err(DecodeError::InvalidType {
                tag: 2,
                pool: 0x64b7d28
            })
        );
        assert_eq!(
            other.events,
            [
                Event::InvalidType {
                    tag: 2,
                    pool: 0x64b7d28
                },
                Event::DropValue { tag: 15 }
            ]
        );
    }
}
