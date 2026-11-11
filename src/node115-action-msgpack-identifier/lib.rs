//! Bounded MessagePack `Action` marker dispatch from node #115.
#![forbid(unsafe_code)]

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadKind {
    Marker,
    Length,
    Payload,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EofSource {
    StaticMessage,
    SimpleUnexpectedEof,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PanicKind {
    InvalidMarker(u8),
    DepthUnderflow,
    DepthOverflow,
}

#[derive(Debug, PartialEq, Eq)]
pub enum DecodeError<E> {
    UnexpectedEof {
        result_tag: u8,
        kind: ReadKind,
        source: EofSource,
    },
    ReservedMarker,
    DepthLimit,
    LengthMismatch {
        expected: u32,
        actual: u32,
    },
    InvalidUtf8 {
        valid_up_to: usize,
        error_len: Option<u8>,
    },
    Visitor(E),
    Panic(PanicKind),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeekedMarker {
    pub tag: u8,
    pub payload: u8,
}

/// Caller-owned state observed by the marker-dispatch copies.
#[derive(Debug)]
pub struct Deserializer<'a> {
    input: &'a [u8],
    position: usize,
    peeked: Option<PeekedMarker>,
    depth: u16,
}

impl<'a> Deserializer<'a> {
    pub fn new(input: &'a [u8], depth: u16) -> Self {
        Self {
            input,
            position: 0,
            peeked: None,
            depth,
        }
    }

    pub fn with_peeked(input: &'a [u8], tag: u8, payload: u8, depth: u16) -> Self {
        Self {
            input,
            position: 0,
            peeked: Some(PeekedMarker { tag, payload }),
            depth,
        }
    }

    pub fn position(&self) -> usize {
        self.position
    }

    pub fn peeked(&self) -> Option<PeekedMarker> {
        self.peeked
    }

    pub fn depth(&self) -> u16 {
        self.depth
    }

    pub fn set_depth(&mut self, depth: u16) {
        self.depth = depth;
    }

    pub fn remaining(&self) -> &'a [u8] {
        &self.input[self.position..]
    }

    pub fn consume(&mut self, count: usize) -> bool {
        if count > self.input.len().saturating_sub(self.position) {
            false
        } else {
            self.position += count;
            true
        }
    }

    fn range(&self, start: usize, end: usize) -> &'a [u8] {
        &self.input[start..end]
    }

    fn take_marker(&mut self) -> Result<(u8, u8), DecodeError<core::convert::Infallible>> {
        let marker = if let Some(peeked) = self.peeked.take() {
            peeked
        } else if self.position < self.input.len() {
            let raw = self.input[self.position];
            self.position += 1;
            let (tag, payload) = classify(raw);
            PeekedMarker { tag, payload }
        } else {
            return Err(DecodeError::UnexpectedEof {
                result_tag: 0,
                kind: ReadKind::Marker,
                source: EofSource::StaticMessage,
            });
        };
        Ok((marker.tag, marker.payload))
    }

    fn read_length(&mut self, width: usize) -> Result<u32, DecodeError<core::convert::Infallible>> {
        let available = self.input.len().saturating_sub(self.position);
        if available < width {
            // The observed two- and four-byte readers consume a short tail;
            // the one-byte reader leaves its cursor unchanged.
            if width > 1 {
                self.position = self.input.len();
            }
            return Err(DecodeError::UnexpectedEof {
                result_tag: 1,
                kind: ReadKind::Length,
                source: EofSource::StaticMessage,
            });
        }

        let bytes = &self.input[self.position..self.position + width];
        let mut value = 0u32;
        for byte in bytes {
            value = (value << 8) | u32::from(*byte);
        }
        self.position += width;
        Ok(value)
    }

    fn take_payload(
        &mut self,
        length: u32,
    ) -> Result<(usize, usize), DecodeError<core::convert::Infallible>> {
        let length = length as usize;
        let start = self.position;
        if length > self.input.len().saturating_sub(start) {
            return Err(DecodeError::UnexpectedEof {
                result_tag: 1,
                kind: ReadKind::Payload,
                source: EofSource::SimpleUnexpectedEof,
            });
        }
        let end = start + length;
        self.position = end;
        Ok((start, end))
    }

    fn enter_nested(&mut self) -> Result<(), DecodeError<core::convert::Infallible>> {
        let Some(next) = self.depth.checked_sub(1) else {
            return Err(DecodeError::Panic(PanicKind::DepthUnderflow));
        };
        self.depth = next;
        if next == 0 {
            return Err(DecodeError::DepthLimit);
        }
        Ok(())
    }

    fn restore_nested(&mut self) -> Result<(), DecodeError<core::convert::Infallible>> {
        let Some(next) = self.depth.checked_add(1) else {
            return Err(DecodeError::Panic(PanicKind::DepthOverflow));
        };
        self.depth = next;
        Ok(())
    }
}

/// The seven call roles made by the bounded marker dispatcher.
///
/// These are project-authored adapter contracts, not the node's original
/// private helper ABIs. Visitors may consume input or update the depth state.
pub trait Visitors {
    type Value;
    type Error;

    fn scalar(
        &mut self,
        deserializer: &mut Deserializer<'_>,
        tag: u8,
        payload: u8,
    ) -> Result<Self::Value, Self::Error>;

    fn visit_str(
        &mut self,
        deserializer: &mut Deserializer<'_>,
        value: &str,
    ) -> Result<Self::Value, Self::Error>;

    fn visit_bytes(
        &mut self,
        deserializer: &mut Deserializer<'_>,
        value: &[u8],
    ) -> Result<Self::Value, Self::Error>;

    fn visit_byte_sequence(
        &mut self,
        deserializer: &mut Deserializer<'_>,
        value: &[u8],
    ) -> Result<Self::Value, Self::Error>;

    fn visit_map(&mut self, length: u32) -> Result<Self::Value, Self::Error>;

    fn visit_sequence(&mut self, length: u32) -> Result<Self::Value, Self::Error>;

    fn visit_extension(
        &mut self,
        deserializer: &mut Deserializer<'_>,
        length: u32,
    ) -> Result<Self::Value, Self::Error>;
}

/// Dispatches one MessagePack value through the target-observed visitor route.
///
/// Any nonzero `binary_as_bytes` byte selects `visit_bytes`; zero selects the
/// byte-sequence visitor. Which upstream caller supplies each value is not
/// established by the evidence packet. Result errors model selected control
/// flow, not the native error layout.
pub fn decode_action<V: Visitors>(
    deserializer: &mut Deserializer<'_>,
    binary_as_bytes: u8,
    visitors: &mut V,
) -> Result<V::Value, DecodeError<V::Error>> {
    let (tag, payload) = deserializer.take_marker().map_err(widen_infallible)?;

    match tag {
        0x00 | 0xe0 | 0xc0 | 0xc2 | 0xc3 | 0xca..=0xd3 => visitors
            .scalar(deserializer, tag, payload)
            .map_err(DecodeError::Visitor),
        0xc1 => Err(DecodeError::ReservedMarker),
        0xa0 | 0xd9 | 0xda | 0xdb => {
            let length = if tag == 0xa0 {
                u32::from(payload)
            } else {
                deserializer
                    .read_length(length_width(tag))
                    .map_err(widen_infallible)?
            };
            let (start, end) = deserializer
                .take_payload(length)
                .map_err(widen_infallible)?;
            let bytes = deserializer.range(start, end);
            match core::str::from_utf8(bytes) {
                Ok(value) => visitors
                    .visit_str(deserializer, value)
                    .map_err(DecodeError::Visitor),
                Err(error) => match visitors.visit_bytes(deserializer, bytes) {
                    Ok(value) => Ok(value),
                    Err(_) => Err(DecodeError::InvalidUtf8 {
                        valid_up_to: error.valid_up_to(),
                        error_len: error.error_len().map(|len| len as u8),
                    }),
                },
            }
        }
        0xc4..=0xc6 => {
            let length = deserializer
                .read_length(length_width(tag))
                .map_err(widen_infallible)?;
            let (start, end) = deserializer
                .take_payload(length)
                .map_err(widen_infallible)?;
            let bytes = deserializer.range(start, end);
            if binary_as_bytes != 0 {
                visitors
                    .visit_bytes(deserializer, bytes)
                    .map_err(DecodeError::Visitor)
            } else {
                visitors
                    .visit_byte_sequence(deserializer, bytes)
                    .map_err(DecodeError::Visitor)
            }
        }
        0x80 | 0xde | 0xdf | 0x90 | 0xdc | 0xdd => {
            let length = if tag == 0x80 || tag == 0x90 {
                u32::from(payload)
            } else {
                deserializer
                    .read_length(length_width(tag))
                    .map_err(widen_infallible)?
            };
            deserializer.enter_nested().map_err(widen_infallible)?;
            let result = if tag == 0x80 || tag == 0xde || tag == 0xdf {
                visitors.visit_map(length)
            } else {
                visitors.visit_sequence(length)
            };
            let value = result.map_err(DecodeError::Visitor)?;
            deserializer.restore_nested().map_err(widen_infallible)?;
            if length == 0 {
                Ok(value)
            } else {
                Err(DecodeError::LengthMismatch {
                    expected: 0,
                    actual: length,
                })
            }
        }
        0xc7..=0xc9 | 0xd4..=0xd8 => {
            let length = if (0xd4..=0xd8).contains(&tag) {
                1u32 << (tag - 0xd4)
            } else {
                deserializer
                    .read_length(length_width(tag))
                    .map_err(widen_infallible)?
            };
            deserializer.enter_nested().map_err(widen_infallible)?;
            let result = visitors.visit_extension(deserializer, length);
            deserializer.restore_nested().map_err(widen_infallible)?;
            result.map_err(DecodeError::Visitor)
        }
        other => Err(DecodeError::Panic(PanicKind::InvalidMarker(other))),
    }
}

fn widen_infallible<E>(error: DecodeError<core::convert::Infallible>) -> DecodeError<E> {
    match error {
        DecodeError::UnexpectedEof {
            result_tag,
            kind,
            source,
        } => DecodeError::UnexpectedEof {
            result_tag,
            kind,
            source,
        },
        DecodeError::ReservedMarker => DecodeError::ReservedMarker,
        DecodeError::DepthLimit => DecodeError::DepthLimit,
        DecodeError::LengthMismatch { expected, actual } => {
            DecodeError::LengthMismatch { expected, actual }
        }
        DecodeError::InvalidUtf8 {
            valid_up_to,
            error_len,
        } => DecodeError::InvalidUtf8 {
            valid_up_to,
            error_len,
        },
        DecodeError::Visitor(value) => match value {},
        DecodeError::Panic(kind) => DecodeError::Panic(kind),
    }
}

fn classify(marker: u8) -> (u8, u8) {
    match marker {
        0x00..=0x7f => (0x00, marker),
        0x80..=0x8f => (0x80, marker & 0x0f),
        0x90..=0x9f => (0x90, marker & 0x0f),
        0xa0..=0xbf => (0xa0, marker & 0x1f),
        0xe0..=0xff => (0xe0, marker),
        _ => (marker, 0),
    }
}

fn length_width(tag: u8) -> usize {
    match tag {
        0xc4 | 0xc7 | 0xd9 => 1,
        0xc5 | 0xc8 | 0xda | 0xdc | 0xde => 2,
        0xc6 | 0xc9 | 0xdb | 0xdd | 0xdf => 4,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, Eq)]
    enum Value {
        Scalar(u8, u8),
        Text(String),
        Bytes(Vec<u8>),
        ByteSequence(Vec<u8>),
        Map(u32),
        Sequence(u32),
        Extension(u32),
    }

    #[derive(Debug, PartialEq, Eq)]
    struct VisitorError;

    #[derive(Default)]
    struct TestVisitors {
        fail_bytes: bool,
        fail_map: bool,
        set_depth: Option<u16>,
    }

    impl Visitors for TestVisitors {
        type Value = Value;
        type Error = VisitorError;

        fn scalar(
            &mut self,
            _: &mut Deserializer<'_>,
            tag: u8,
            payload: u8,
        ) -> Result<Self::Value, Self::Error> {
            Ok(Value::Scalar(tag, payload))
        }

        fn visit_str(
            &mut self,
            _: &mut Deserializer<'_>,
            value: &str,
        ) -> Result<Self::Value, Self::Error> {
            Ok(Value::Text(value.to_owned()))
        }

        fn visit_bytes(
            &mut self,
            _: &mut Deserializer<'_>,
            value: &[u8],
        ) -> Result<Self::Value, Self::Error> {
            if self.fail_bytes {
                Err(VisitorError)
            } else {
                Ok(Value::Bytes(value.to_vec()))
            }
        }

        fn visit_byte_sequence(
            &mut self,
            _: &mut Deserializer<'_>,
            value: &[u8],
        ) -> Result<Self::Value, Self::Error> {
            Ok(Value::ByteSequence(value.to_vec()))
        }

        fn visit_map(&mut self, length: u32) -> Result<Self::Value, Self::Error> {
            if self.fail_map {
                Err(VisitorError)
            } else {
                Ok(Value::Map(length))
            }
        }

        fn visit_sequence(&mut self, length: u32) -> Result<Self::Value, Self::Error> {
            Ok(Value::Sequence(length))
        }

        fn visit_extension(
            &mut self,
            deserializer: &mut Deserializer<'_>,
            length: u32,
        ) -> Result<Self::Value, Self::Error> {
            if let Some(depth) = self.set_depth {
                deserializer.set_depth(depth);
            }
            Ok(Value::Extension(length))
        }
    }

    #[test]
    fn marker_normalization_covers_fixints_and_fixed_collections() {
        let mut visitor = TestVisitors::default();
        for (input, expected) in [
            (&[0x2a][..], Value::Scalar(0x00, 0x2a)),
            (&[0xe1][..], Value::Scalar(0xe0, 0xe1)),
            (&[0x80][..], Value::Map(0)),
            (&[0x90][..], Value::Sequence(0)),
            (&[0xa3, b'c', b'a', b't'][..], Value::Text("cat".into())),
        ] {
            let mut deserializer = Deserializer::new(input, 8);
            assert_eq!(
                decode_action(&mut deserializer, 0, &mut visitor),
                Ok(expected)
            );
        }
    }

    #[test]
    fn peeked_marker_skips_the_input_marker_and_is_cleared() {
        let mut deserializer = Deserializer::with_peeked(b"*", 0xa0, 1, 8);
        let mut visitor = TestVisitors::default();

        assert_eq!(
            decode_action(&mut deserializer, 0, &mut visitor),
            Ok(Value::Text("*".into()))
        );
        assert_eq!(deserializer.position(), 1);
        assert_eq!(deserializer.peeked(), None);
    }

    #[test]
    fn length_and_payload_eof_keep_the_observed_cursor_positions() {
        let mut visitor = TestVisitors::default();
        let mut one_byte = Deserializer::new(&[0xd9], 8);
        assert_eq!(
            decode_action(&mut one_byte, 0, &mut visitor),
            Err(DecodeError::UnexpectedEof {
                result_tag: 1,
                kind: ReadKind::Length,
                source: EofSource::StaticMessage,
            })
        );
        assert_eq!(one_byte.position(), 1);

        let mut short_two = Deserializer::new(&[0xda, 0x00], 8);
        assert!(matches!(
            decode_action(&mut short_two, 0, &mut visitor),
            Err(DecodeError::UnexpectedEof {
                kind: ReadKind::Length,
                source: EofSource::StaticMessage,
                ..
            })
        ));
        assert_eq!(short_two.position(), 2);

        let mut short_four = Deserializer::new(&[0xdb, 1, 2], 8);
        assert!(matches!(
            decode_action(&mut short_four, 0, &mut visitor),
            Err(DecodeError::UnexpectedEof {
                kind: ReadKind::Length,
                source: EofSource::StaticMessage,
                ..
            })
        ));
        assert_eq!(short_four.position(), 3);

        let mut short_payload = Deserializer::new(&[0xd9, 3, b'a'], 8);
        assert!(matches!(
            decode_action(&mut short_payload, 0, &mut visitor),
            Err(DecodeError::UnexpectedEof {
                kind: ReadKind::Payload,
                source: EofSource::SimpleUnexpectedEof,
                ..
            })
        ));
        assert_eq!(short_payload.position(), 2);
    }

    #[test]
    fn invalid_utf8_falls_back_to_bytes_then_reports_utf8_on_error() {
        let input = [0xa2, 0xff, b'x'];
        let mut deserializer = Deserializer::new(&input, 8);
        let mut visitor = TestVisitors::default();
        assert_eq!(
            decode_action(&mut deserializer, 0, &mut visitor),
            Ok(Value::Bytes(vec![0xff, b'x']))
        );

        let mut deserializer = Deserializer::new(&input, 8);
        let mut visitor = TestVisitors {
            fail_bytes: true,
            ..TestVisitors::default()
        };
        assert_eq!(
            decode_action(&mut deserializer, 0, &mut visitor),
            Err(DecodeError::InvalidUtf8 {
                valid_up_to: 0,
                error_len: Some(1),
            })
        );
        assert_eq!(deserializer.position(), input.len());
    }

    #[test]
    fn binary_flag_selects_bytes_or_sequence_visitor() {
        let input = [0xc4, 2, b'o', b'k'];
        let mut deserializer = Deserializer::new(&input, 8);
        let mut visitor = TestVisitors::default();
        assert_eq!(
            decode_action(&mut deserializer, 1, &mut visitor),
            Ok(Value::Bytes(b"ok".to_vec()))
        );

        let mut deserializer = Deserializer::new(&input, 8);
        assert_eq!(
            decode_action(&mut deserializer, 0, &mut visitor),
            Ok(Value::ByteSequence(b"ok".to_vec()))
        );
    }

    #[test]
    fn sixteen_and_thirty_two_bit_lengths_are_big_endian() {
        let mut visitor = TestVisitors::default();
        let mut string16 = Deserializer::new(&[0xda, 0, 3, b'c', b'a', b't'], 8);
        assert_eq!(
            decode_action(&mut string16, 0, &mut visitor),
            Ok(Value::Text("cat".into()))
        );
        assert_eq!(string16.position(), 6);

        let mut string32 = Deserializer::new(&[0xdb, 0, 0, 0, 0], 8);
        assert_eq!(
            decode_action(&mut string32, 0, &mut visitor),
            Ok(Value::Text(String::new()))
        );
        assert_eq!(string32.position(), 5);

        let mut array16 = Deserializer::new(&[0xdc, 0, 0], 8);
        assert_eq!(
            decode_action(&mut array16, 0, &mut visitor),
            Ok(Value::Sequence(0))
        );
        assert_eq!(array16.position(), 3);
    }

    #[test]
    fn container_depth_errors_and_restoration_match_the_dispatch_policy() {
        let mut visitor = TestVisitors::default();
        let mut depth_zero = Deserializer::new(&[0x80], 0);
        assert_eq!(
            decode_action(&mut depth_zero, 0, &mut visitor),
            Err(DecodeError::Panic(PanicKind::DepthUnderflow))
        );

        let mut at_limit = Deserializer::new(&[0x80], 1);
        assert_eq!(
            decode_action(&mut at_limit, 0, &mut visitor),
            Err(DecodeError::DepthLimit)
        );
        assert_eq!(at_limit.depth(), 0);

        let mut mismatch = Deserializer::new(&[0x81], 4);
        assert_eq!(
            decode_action(&mut mismatch, 0, &mut visitor),
            Err(DecodeError::LengthMismatch {
                expected: 0,
                actual: 1,
            })
        );
        assert_eq!(mismatch.depth(), 4);

        let mut failed = Deserializer::new(&[0x80], 4);
        let mut visitor = TestVisitors {
            fail_map: true,
            ..TestVisitors::default()
        };
        assert_eq!(
            decode_action(&mut failed, 0, &mut visitor),
            Err(DecodeError::Visitor(VisitorError))
        );
        assert_eq!(failed.depth(), 3);
    }

    #[test]
    fn extension_uses_length_and_restores_the_visitor_depth() {
        let input = [0xd6, 0x7f, 1, 2, 3, 4]; // fixext4
        let mut deserializer = Deserializer::new(&input, 8);
        let mut visitor = TestVisitors {
            set_depth: Some(10),
            ..TestVisitors::default()
        };

        assert_eq!(
            decode_action(&mut deserializer, 0, &mut visitor),
            Ok(Value::Extension(4))
        );
        assert_eq!(deserializer.depth(), 11);
        assert_eq!(deserializer.position(), 1);
    }

    #[test]
    fn extension_length_widths_and_restore_overflow_are_bounded() {
        let mut visitor = TestVisitors::default();
        let mut ext8 = Deserializer::new(&[0xc7, 2], 8);
        assert_eq!(
            decode_action(&mut ext8, 0, &mut visitor),
            Ok(Value::Extension(2))
        );
        assert_eq!(ext8.position(), 2);

        let mut ext16 = Deserializer::new(&[0xc8, 0, 4], 8);
        assert_eq!(
            decode_action(&mut ext16, 0, &mut visitor),
            Ok(Value::Extension(4))
        );
        assert_eq!(ext16.position(), 3);

        let mut overflow = Deserializer::new(&[0xd4], 8);
        let mut visitor = TestVisitors {
            set_depth: Some(u16::MAX),
            ..TestVisitors::default()
        };
        assert_eq!(
            decode_action(&mut overflow, 0, &mut visitor),
            Err(DecodeError::Panic(PanicKind::DepthOverflow))
        );
        assert_eq!(overflow.depth(), u16::MAX);
    }

    #[test]
    fn reserved_marker_and_empty_input_have_distinct_outcomes() {
        let mut visitor = TestVisitors::default();
        let mut reserved = Deserializer::new(&[0xc1], 8);
        assert_eq!(
            decode_action(&mut reserved, 0, &mut visitor),
            Err(DecodeError::ReservedMarker)
        );
        let mut empty = Deserializer::new(&[], 8);
        assert_eq!(
            decode_action(&mut empty, 0, &mut visitor),
            Err(DecodeError::UnexpectedEof {
                result_tag: 0,
                kind: ReadKind::Marker,
                source: EofSource::StaticMessage,
            })
        );
    }
}
