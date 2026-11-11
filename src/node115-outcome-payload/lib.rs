//! Outcome payload readers from node #115, on the recognized-field domain.
//! Unknown values and type-error visitors are explicit analysis boundaries.
//! Byte strings deliberately do not invent raw UTF-8 validation.
#[path = "../node115-json-string-scanner/lib.rs"]
mod scanner;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Variant {
    StandaloneOutcome,
    QuestionOutcome,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Payload {
    StandaloneOutcome { side_names: [Vec<u8>; 2] },
    QuestionOutcome { parent: Vec<u8> },
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Failure {
    /// Native parser error discriminant, without allocation or formatting.
    Code(u64),
    MissingField(&'static str),
    DuplicateField(&'static str),
    InvalidLength {
        actual: usize,
        expected: usize,
    },
    /// Stops before the native ignored-value helper, after the colon.
    UnknownValue {
        key: Vec<u8>,
    },
    /// Stops before 0x1d76fd0, whose cursor effects are not reconstructed here.
    TypeVisitor {
        expected: &'static str,
    },
    /// Native checked depth-underflow assertion, not a JSON parse error.
    ZeroDepth,
}
impl Failure {
    fn boundary(&self) -> bool {
        matches!(
            self,
            Self::UnknownValue { .. } | Self::TypeVisitor { .. } | Self::ZeroDepth
        )
    }
}
pub struct Reader<'a> {
    pub input: &'a [u8],
    pub cursor: usize,
    pub depth: Option<u8>,
}
impl<'a> Reader<'a> {
    pub fn new(input: &'a [u8]) -> Self {
        Self {
            input,
            cursor: 0,
            depth: Some(128),
        }
    }
    fn peek(&mut self) -> Option<u8> {
        while matches!(
            self.input.get(self.cursor),
            Some(b' ' | b'\t' | b'\r' | b'\n')
        ) {
            self.cursor += 1;
        }
        self.input.get(self.cursor).copied()
    }
    fn enter(&mut self) -> Result<(), Failure> {
        if let Some(d) = &mut self.depth {
            if *d == 0 {
                return Err(Failure::ZeroDepth);
            }
            *d -= 1;
            if *d == 0 {
                return Err(Failure::Code(24));
            }
        }
        self.cursor += 1;
        Ok(())
    }
    fn finish<T>(&mut self, result: Result<T, Failure>, object: bool) -> Result<T, Failure> {
        // A boundary is a suspended native call, not a completed native error.
        if result.as_ref().err().is_some_and(Failure::boundary) {
            return result;
        }
        if let Some(d) = &mut self.depth {
            *d += 1;
        }
        let end = self.end(object);
        match result {
            Err(e) => Err(e),
            Ok(value) => end.map(|()| value),
        }
    }
    fn end(&mut self, object: bool) -> Result<(), Failure> {
        match self.peek() {
            Some(c) if c == if object { b'}' } else { b']' } => {
                self.cursor += 1;
                Ok(())
            }
            None => Err(Failure::Code(if object { 3 } else { 2 })),
            Some(b',') if object => Err(Failure::Code(21)),
            Some(b',') => {
                self.cursor += 1;
                if self.peek() == Some(b']') {
                    Err(Failure::Code(21))
                } else {
                    Err(Failure::Code(22))
                }
            }
            _ => Err(Failure::Code(22)),
        }
    }
    fn next(&mut self, first: &mut bool, object: bool) -> Result<bool, Failure> {
        let close = if object { b'}' } else { b']' };
        let b = self
            .peek()
            .ok_or(Failure::Code(if object { 3 } else { 2 }))?;
        if b == close {
            return Ok(false);
        }
        let key = if *first {
            *first = false;
            b
        } else {
            if b != b',' {
                return Err(Failure::Code(if object { 8 } else { 7 }));
            }
            self.cursor += 1;
            let b = self.peek().ok_or(Failure::Code(5))?;
            if b == close {
                return Err(Failure::Code(21));
            }
            b
        };
        if object && key != b'"' {
            return Err(Failure::Code(17));
        }
        Ok(true)
    }
    fn colon(&mut self) -> Result<(), Failure> {
        match self.peek() {
            Some(b':') => {
                self.cursor += 1;
                Ok(())
            }
            None => Err(Failure::Code(3)),
            _ => Err(Failure::Code(6)),
        }
    }
    fn string(&mut self) -> Result<Vec<u8>, Failure> {
        match self.peek() {
            Some(b'"') => self.cursor += 1,
            None => return Err(Failure::Code(5)),
            _ => return Err(Failure::TypeVisitor { expected: "string" }),
        }
        let mut scratch = Vec::new();
        let bytes = scanner::scan(self.input, &mut self.cursor, &mut scratch)
            .map_err(|e| Failure::Code(e.code))?;
        Ok(match bytes {
            scanner::Output::Borrowed(b) | scanner::Output::Scratch(b) => b.to_vec(),
        })
    }
    fn pair(&mut self) -> Result<[Vec<u8>; 2], Failure> {
        match self.peek() {
            Some(b'[') => (),
            None => return Err(Failure::Code(5)),
            _ => {
                return Err(Failure::TypeVisitor {
                    expected: "two-string array",
                })
            }
        }
        self.enter()?;
        let result = (|| {
            let mut first = true;
            if !self.next(&mut first, false)? {
                return Err(Failure::InvalidLength {
                    actual: 0,
                    expected: 2,
                });
            }
            let a = self.string()?;
            if !self.next(&mut first, false)? {
                return Err(Failure::InvalidLength {
                    actual: 1,
                    expected: 2,
                });
            }
            let b = self.string()?;
            Ok([a, b])
        })();
        self.finish(result, false)
    }
    fn value(&mut self, variant: Variant) -> Result<Payload, Failure> {
        match variant {
            Variant::StandaloneOutcome => self
                .pair()
                .map(|side_names| Payload::StandaloneOutcome { side_names }),
            Variant::QuestionOutcome => self
                .string()
                .map(|parent| Payload::QuestionOutcome { parent }),
        }
    }
    /// Begins at the payload, after the enum-name/colon wrapper has selected it.
    /// Success consumes the payload delimiter but leaves the outer enum wrapper.
    pub fn payload(&mut self, variant: Variant) -> Result<Payload, Failure> {
        let object = match self.peek() {
            Some(b'{') => true,
            Some(b'[') => false,
            None => return Err(Failure::Code(5)),
            _ => {
                return Err(Failure::TypeVisitor {
                    expected: "outcome payload",
                })
            }
        };
        self.enter()?;
        let field = match variant {
            Variant::StandaloneOutcome => "side_names",
            Variant::QuestionOutcome => "parent",
        };
        let result = (|| {
            let mut first = true;
            if !object {
                if !self.next(&mut first, false)? {
                    return Err(Failure::InvalidLength {
                        actual: 0,
                        expected: 1,
                    });
                }
                return self.value(variant);
            }
            let mut value = None;
            while self.next(&mut first, true)? {
                let key = self.string()?;
                if key == field.as_bytes() {
                    // Duplicate detection precedes colon consumption and decoding.
                    if value.is_some() {
                        return Err(Failure::DuplicateField(field));
                    }
                    self.colon()?;
                    value = Some(self.value(variant)?);
                } else {
                    self.colon()?;
                    return Err(Failure::UnknownValue { key });
                }
            }
            value.ok_or(Failure::MissingField(field))
        })();
        self.finish(result, object)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn both_forms_and_owning_layout_values() {
        for b in [
            br#"{"side_names":["yes","no"]}"#.as_slice(),
            br#"[["yes","no"]]"#,
        ] {
            let mut r = Reader::new(b);
            assert_eq!(
                r.payload(Variant::StandaloneOutcome),
                Ok(Payload::StandaloneOutcome {
                    side_names: [b"yes".to_vec(), b"no".to_vec()]
                })
            );
            assert_eq!((r.cursor, r.depth), (b.len(), Some(128)));
        }
        for b in [
            br#"{"parent":"question-1"}"#.as_slice(),
            br#"["question-1"]"#,
        ] {
            let mut r = Reader::new(b);
            assert_eq!(
                r.payload(Variant::QuestionOutcome),
                Ok(Payload::QuestionOutcome {
                    parent: b"question-1".to_vec()
                })
            );
            assert_eq!((r.cursor, r.depth), (b.len(), Some(128)));
        }
    }
    #[test]
    fn decoded_keys_duplicates_and_cursor_precedence() {
        let b = br#"{"par\u0065nt":"x", "parent" : "y"}"#;
        let mut r = Reader::new(b);
        assert_eq!(
            r.payload(Variant::QuestionOutcome),
            Err(Failure::DuplicateField("parent"))
        );
        assert_eq!(&b[r.cursor..], br#": "y"}"#); // end-object helper skips the whitespace.
        assert_eq!(r.depth, Some(128));
        let mut r = Reader::new(br#"{"parent":"x", "parent"}"#);
        assert_eq!(
            r.payload(Variant::QuestionOutcome),
            Err(Failure::DuplicateField("parent"))
        );
        assert_eq!(r.cursor, r.input.len()); // cleanup consumes }, duplicate error wins.
    }
    #[test]
    fn exact_cardinality_missing_and_trailing_commas() {
        for (b, error) in [
            (
                b"[]".as_slice(),
                Failure::InvalidLength {
                    actual: 0,
                    expected: 1,
                },
            ),
            (
                b"[[]]",
                Failure::InvalidLength {
                    actual: 0,
                    expected: 2,
                },
            ),
            (
                br#"[["a"]]"#,
                Failure::InvalidLength {
                    actual: 1,
                    expected: 2,
                },
            ),
            (br#"[["a","b","c"]]"#, Failure::Code(22)),
            (br#"[["a","b",]]"#, Failure::Code(21)),
            (br#"{"side_names":["a","b"],}"#, Failure::Code(21)),
            (b"{}", Failure::MissingField("side_names")),
        ] {
            let mut r = Reader::new(b);
            assert_eq!(r.payload(Variant::StandaloneOutcome), Err(error), "{b:?}");
            assert_eq!(r.depth, Some(128));
        }
    }
    #[test]
    fn strings_reuse_scanner_without_utf8_assumption() {
        let mut r = Reader::new(b"{\"parent\":\"\xff\"}");
        assert_eq!(
            r.payload(Variant::QuestionOutcome),
            Ok(Payload::QuestionOutcome { parent: vec![255] })
        );
        let mut r = Reader::new(br#"{"parent":"\uD83D\uDE80\n"}suffix"#);
        assert_eq!(
            r.payload(Variant::QuestionOutcome),
            Ok(Payload::QuestionOutcome {
                parent: "🚀\n".as_bytes().to_vec()
            })
        );
        assert_eq!(&r.input[r.cursor..], b"suffix");
    }
    #[test]
    fn depth_failure_and_explicit_boundaries() {
        let mut r = Reader::new(br#"[["a","b"]]"#);
        r.depth = Some(2);
        assert_eq!(
            r.payload(Variant::StandaloneOutcome),
            Err(Failure::Code(24))
        );
        assert_eq!((r.cursor, r.depth), (1, Some(1))); // inner failed entry does not restore its debit.
        let mut r = Reader::new(br#"{"unknown": [1,2]}"#);
        assert_eq!(
            r.payload(Variant::QuestionOutcome),
            Err(Failure::UnknownValue {
                key: b"unknown".to_vec()
            })
        );
        assert_eq!(&r.input[r.cursor..], b" [1,2]}");
        assert_eq!(r.depth, Some(127)); // suspended before the native helper.
        let mut r = Reader::new(br#"{"parent":0}"#);
        assert_eq!(
            r.payload(Variant::QuestionOutcome),
            Err(Failure::TypeVisitor { expected: "string" })
        );
        assert_eq!(&r.input[r.cursor..], b"0}");
        let mut r = Reader::new(b"{}");
        r.depth = Some(0);
        assert_eq!(r.payload(Variant::QuestionOutcome), Err(Failure::ZeroDepth));
        assert_eq!(r.cursor, 0);
    }
}
