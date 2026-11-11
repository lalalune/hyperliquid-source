//! JSON error position and 40-byte wrapper replacement on the selected valid
//! reader path. Native CPU dispatch, allocation failure and payload destructors
//! are not implemented; opaque payload bytes retain their exact representation.
#[derive(Clone, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct ErrorRecord {
    pub payload: [u8; 24],
    pub line: u64,
    pub column: u64,
}
#[derive(Debug, PartialEq, Eq)]
pub enum Finished {
    Kept(Box<ErrorRecord>),
    Repositioned(Box<ErrorRecord>),
    BeforeCursorFailure(Box<ErrorRecord>),
}
/// Positions count LF only and columns are byte offsets, not Unicode characters.
pub fn position(input: &[u8], cursor: usize) -> Option<(u64, u64)> {
    let prefix = input.get(..cursor)?;
    let start = prefix
        .iter()
        .rposition(|&b| b == b'\n')
        .map_or(0, |i| i + 1);
    let line = 1 + input[..start].iter().filter(|&&b| b == b'\n').count() as u64;
    Some((line, (cursor - start) as u64))
}
/// Existing nonzero line preserves pointer identity and bypasses the reader.
/// Replacement allocates before releasing the original 40-byte wrapper.
pub fn finish(error: Box<ErrorRecord>, input: &[u8], cursor: usize) -> Finished {
    if error.line != 0 {
        return Finished::Kept(error);
    }
    let Some((line, column)) = position(input, cursor) else {
        return Finished::BeforeCursorFailure(error);
    };
    let replacement = Box::new(ErrorRecord {
        payload: error.payload,
        line,
        column,
    });
    drop(error);
    Finished::Repositioned(replacement)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn lines_are_one_based_columns_zero_based_bytes() {
        let input = "a\r\nbé\nc".as_bytes();
        let expected = [
            (1, 0),
            (1, 1),
            (1, 2),
            (2, 0),
            (2, 1),
            (2, 2),
            (2, 3),
            (3, 0),
            (3, 1),
        ];
        for (cursor, want) in expected.into_iter().enumerate() {
            assert_eq!(position(input, cursor), Some(want));
        }
        assert_eq!(position(input, input.len() + 1), None);
    }
    #[test]
    fn existing_position_bypasses_reader_and_preserves_all_bytes() {
        let record = Box::new(ErrorRecord {
            payload: [0xa5; 24],
            line: 7,
            column: 99,
        });
        let pointer = &*record as *const ErrorRecord;
        let Finished::Kept(result) = finish(record, &[], usize::MAX) else {
            panic!()
        };
        assert_eq!(&*result as *const ErrorRecord, pointer);
        assert_eq!(result.line, 7);
        assert_eq!(result.column, 99);
        assert_eq!(result.payload, [0xa5; 24]);
    }
    #[test]
    fn replacement_preserves_payload_and_allocates_before_free() {
        let record = Box::new(ErrorRecord {
            payload: std::array::from_fn(|i| i as u8),
            line: 0,
            column: 999,
        });
        let pointer = &*record as *const ErrorRecord;
        let Finished::Repositioned(result) = finish(record, b"first\nlast", 8) else {
            panic!()
        };
        assert_ne!(&*result as *const ErrorRecord, pointer);
        assert_eq!((result.line, result.column), (2, 2));
        assert_eq!(result.payload, std::array::from_fn(|i| i as u8));
        assert_eq!(std::mem::size_of::<ErrorRecord>(), 40);
    }
    #[test]
    fn invalid_cursor_retains_owned_error_at_boundary() {
        let record = Box::new(ErrorRecord {
            payload: [3; 24],
            line: 0,
            column: 99,
        });
        let pointer = &*record as *const ErrorRecord;
        let Finished::BeforeCursorFailure(result) = finish(record, b"a", 2) else {
            panic!()
        };
        assert_eq!(&*result as *const ErrorRecord, pointer);
        assert_eq!(result.column, 99);
    }
    #[test]
    fn every_short_newline_pattern_against_forward_oracle() {
        let mut cases = 0;
        for length in 0..=12 {
            for mask in 0..1usize << length {
                let input: Vec<u8> = (0..length)
                    .map(|i| if mask & (1 << i) == 0 { b'x' } else { b'\n' })
                    .collect();
                let (mut line, mut col) = (1, 0);
                for cursor in 0..=length {
                    assert_eq!(position(&input, cursor), Some((line, col)));
                    cases += 1;
                    if let Some(&b) = input.get(cursor) {
                        if b == b'\n' {
                            line += 1;
                            col = 0;
                        } else {
                            col += 1;
                        }
                    }
                }
            }
        }
        assert_eq!(cases, 98305);
    }
}
