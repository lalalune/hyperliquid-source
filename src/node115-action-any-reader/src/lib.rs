//! Bounded model of the node #115 MessagePack `deserialize_any` state machine.

pub const TARGET_SHA256: &str = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301";
const SIMPLE_EOF: u64 = 0x0025_0000_0003;
const STATIC_EOF: u64 = 0x641_ccb0;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CalleeResult {
    Ok,
    Err,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VisitorKnob {
    pub result: CalleeResult,
    pub remaining: Option<u32>,
    pub depth_after: Option<u16>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResultKind {
    CalleeOut(&'static str, CalleeResult),
    CalleeErr(&'static str),
    Io {
        kind: u8,
        code: u64,
    },
    TypeMismatch(u8),
    LengthMismatch(u32),
    Utf8 {
        valid_up_to: usize,
        error_len: Option<u8>,
    },
    DepthLimit,
    PanicAdd(u64),
    PanicSub(u64),
    UnreachableTag(u8),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Outcome {
    pub result: ResultKind,
    pub input_position: usize,
    pub peek_consumed: bool,
    pub depth: u16,
}

/// Model the observed state/result contract. Callee internals remain supplied
/// as knobs; this function does not implement visitors or execute the node.
pub fn deserialize_any(
    input: &[u8],
    peek: Option<(u8, u8)>,
    depth: u16,
    flag: u8,
    knob: VisitorKnob,
) -> Outcome {
    let mut position = 0usize;
    let mut depth = depth;
    let mut calls: Vec<&'static str> = Vec::new();
    let (tag, payload) = match peek {
        Some(value) => value,
        None => {
            if input.is_empty() {
                return finish(
                    ResultKind::Io {
                        kind: 0,
                        code: STATIC_EOF,
                    },
                    position,
                    depth,
                );
            }
            let byte = input[0];
            position = 1;
            if byte < 0x80 {
                (0, byte)
            } else if byte >= 0xe0 {
                (0xe0, byte)
            } else if byte < 0x90 {
                (0x80, byte & 0x0f)
            } else if byte < 0xa0 {
                (0x90, byte & 0x0f)
            } else {
                (if byte < 0xc0 { 0xa0 } else { byte }, byte & 0x1f)
            }
        }
    };

    let mut read_len = |count: usize| -> Option<u32> {
        if input.len().saturating_sub(position) < count {
            if count > 1 {
                position = input.len();
            }
            return None;
        }
        let mut value = 0u32;
        for byte in &input[position..position + count] {
            value = (value << 8) | u32::from(*byte);
        }
        position += count;
        Some(value)
    };

    let outcome = if tag == 0
        || tag == 0xc0
        || tag == 0xc2
        || tag == 0xc3
        || tag == 0xe0
        || (0xca..=0xd3).contains(&tag)
    {
        calls.push("any");
        ResultKind::CalleeOut("any", knob.result)
    } else if tag == 0xc1 {
        ResultKind::TypeMismatch(0xc1)
    } else if tag == 0xa0 {
        string(input, &mut position, payload as u32, knob, &mut calls)
    } else if matches!(tag, 0xd9..=0xdb) {
        let count = match tag {
            0xd9 => 1,
            0xda => 2,
            _ => 4,
        };
        match read_len(count) {
            Some(length) => string(input, &mut position, length, knob, &mut calls),
            None => ResultKind::Io {
                kind: 1,
                code: STATIC_EOF,
            },
        }
    } else if matches!(tag, 0xc4..=0xc6) {
        let count = match tag {
            0xc4 => 1,
            0xc5 => 2,
            _ => 4,
        };
        match read_len(count) {
            Some(length) => binary(input, &mut position, length, flag, knob, &mut calls),
            None => ResultKind::Io {
                kind: 1,
                code: STATIC_EOF,
            },
        }
    } else if tag == 0x80 || tag == 0x90 {
        container(
            if tag == 0x80 { "map" } else { "seq" },
            payload.into(),
            &mut depth,
            knob,
            &mut calls,
        )
    } else if matches!(tag, 0xdc..=0xdf) {
        let count = if matches!(tag, 0xde | 0xdc) { 2 } else { 4 };
        match read_len(count) {
            Some(length) => container(
                if matches!(tag, 0xde | 0xdf) {
                    "map"
                } else {
                    "seq"
                },
                length,
                &mut depth,
                knob,
                &mut calls,
            ),
            None => ResultKind::Io {
                kind: 1,
                code: STATIC_EOF,
            },
        }
    } else if matches!(tag, 0xd4..=0xd8) {
        let length = match tag {
            0xd4 => 1,
            0xd5 => 2,
            0xd6 => 4,
            0xd7 => 8,
            _ => 16,
        };
        extension(length, &mut depth, knob, &mut calls)
    } else if matches!(tag, 0xc7..=0xc9) {
        let count = match tag {
            0xc7 => 1,
            0xc8 => 2,
            _ => 4,
        };
        match read_len(count) {
            Some(length) => extension(length, &mut depth, knob, &mut calls),
            None => ResultKind::Io {
                kind: 1,
                code: STATIC_EOF,
            },
        }
    } else {
        // Non-Marker values route to `ud2` in the observed jump table.
        ResultKind::UnreachableTag(tag)
    };
    finish(outcome, position, depth)
}

fn string(
    input: &[u8],
    position: &mut usize,
    length: u32,
    knob: VisitorKnob,
    calls: &mut Vec<&'static str>,
) -> ResultKind {
    let length = length as usize;
    if input.len().saturating_sub(*position) < length {
        return ResultKind::Io {
            kind: 1,
            code: SIMPLE_EOF,
        };
    }
    let start = *position;
    *position += length;
    let bytes = &input[start..start + length];
    match std::str::from_utf8(bytes) {
        Ok(_) => {
            calls.push("visit_str");
            ResultKind::CalleeOut("visit_str", knob.result)
        }
        Err(error) => {
            calls.push("visit_bytes");
            if knob.result == CalleeResult::Ok {
                ResultKind::CalleeOut("visit_bytes", knob.result)
            } else {
                ResultKind::Utf8 {
                    valid_up_to: error.valid_up_to(),
                    error_len: error.error_len().map(|n| n as u8),
                }
            }
        }
    }
}

fn binary(
    input: &[u8],
    position: &mut usize,
    length: u32,
    flag: u8,
    knob: VisitorKnob,
    calls: &mut Vec<&'static str>,
) -> ResultKind {
    let length = length as usize;
    if input.len().saturating_sub(*position) < length {
        return ResultKind::Io {
            kind: 1,
            code: SIMPLE_EOF,
        };
    }
    let start = *position;
    *position += length;
    if flag != 0 {
        calls.push("visit_bytes");
        ResultKind::CalleeOut("visit_bytes", knob.result)
    } else {
        let _end = start + length;
        calls.push("bytes_seq");
        ResultKind::CalleeOut("bytes_seq", knob.result)
    }
}

fn container(
    kind: &'static str,
    length: u32,
    depth: &mut u16,
    knob: VisitorKnob,
    calls: &mut Vec<&'static str>,
) -> ResultKind {
    let panic = if kind == "map" {
        0x641_f9f8
    } else {
        0x641_f9c8
    };
    if *depth == 0 {
        return ResultKind::PanicSub(panic);
    }
    *depth -= 1;
    if *depth == 0 {
        return ResultKind::DepthLimit;
    }
    let role = if kind == "map" {
        "visit_map"
    } else {
        "visit_seq"
    };
    calls.push(role);
    if let Some(value) = knob.depth_after {
        *depth = value;
    }
    if knob.result == CalleeResult::Err {
        return ResultKind::CalleeErr(role);
    }
    let remaining = knob.remaining.unwrap_or(length);
    if remaining == 0 {
        if *depth == u16::MAX {
            return ResultKind::PanicAdd(if kind == "map" {
                0x641_f9f8
            } else {
                0x641_f9c8
            });
        }
        *depth += 1;
        return ResultKind::CalleeOut(role, knob.result);
    }
    if remaining > length {
        return ResultKind::PanicSub(if kind == "map" {
            0x641_fa10
        } else {
            0x641_f9e0
        });
    }
    if *depth == u16::MAX {
        return ResultKind::PanicAdd(if kind == "map" {
            0x641_f9f8
        } else {
            0x641_f9c8
        });
    }
    *depth += 1;
    ResultKind::LengthMismatch(length - remaining)
}

fn extension(
    length: u32,
    depth: &mut u16,
    knob: VisitorKnob,
    calls: &mut Vec<&'static str>,
) -> ResultKind {
    if *depth == 0 {
        return ResultKind::PanicSub(0x641_f9b0);
    }
    *depth -= 1;
    if *depth == 0 {
        return ResultKind::DepthLimit;
    }
    let _length = length;
    calls.push("visit_ext");
    if let Some(value) = knob.depth_after {
        *depth = value;
    }
    if *depth == u16::MAX {
        return ResultKind::PanicAdd(0x641_f9b0);
    }
    *depth += 1;
    ResultKind::CalleeOut("visit_ext", knob.result)
}

fn finish(result: ResultKind, input_position: usize, depth: u16) -> Outcome {
    Outcome {
        result,
        input_position,
        peek_consumed: true,
        depth,
    }
}

#[cfg(test)]
fn fmt_int(value: u64) -> String {
    if value > 9 {
        format!("{value:#x}")
    } else {
        value.to_string()
    }
}

#[cfg(test)]
fn render(result: &ResultKind) -> String {
    match result {
        ResultKind::CalleeOut(role, CalleeResult::Ok) => format!("(callee_out,{role},(ok,0x2a))"),
        ResultKind::CalleeOut(role, CalleeResult::Err) => format!("(callee_out,{role},(err,5))"),
        ResultKind::CalleeErr(role) => format!("(callee_err,{role})"),
        ResultKind::Io { kind, code } => format!("(io,{kind},{})", fmt_int(*code)),
        ResultKind::TypeMismatch(tag) => format!("(type_mismatch,{})", fmt_int(u64::from(*tag))),
        ResultKind::LengthMismatch(length) => {
            format!("(length_mismatch,{})", fmt_int(u64::from(*length)))
        }
        ResultKind::Utf8 {
            valid_up_to,
            error_len,
        } => format!(
            "(utf8,{}, {})",
            fmt_int(*valid_up_to as u64),
            error_len.map_or_else(|| "-".into(), |n| n.to_string())
        )
        .replace(", ", ","),
        ResultKind::DepthLimit => "(depth)".into(),
        ResultKind::PanicAdd(location) => format!("(panic_add,{})", fmt_int(*location)),
        ResultKind::PanicSub(location) => format!("(panic_sub,{})", fmt_int(*location)),
        ResultKind::UnreachableTag(tag) => format!("(unreachable,{})", fmt_int(u64::from(*tag))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const CASES: &str =
        include_str!("../../../research/work-items/RE-010-action-msgpack-struct-any-115/cases.tsv");

    fn number(value: &str) -> u32 {
        if let Some(hex) = value.strip_prefix("0x") {
            u32::from_str_radix(hex, 16).unwrap()
        } else {
            value.parse().unwrap()
        }
    }

    fn hex_bytes(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    fn expected_class(result: &ResultKind) -> &'static str {
        match result {
            ResultKind::CalleeOut(_, _) => "callee_out",
            ResultKind::CalleeErr(_) => "callee_err",
            ResultKind::Io { .. } => "io",
            ResultKind::TypeMismatch(_) => "type_mismatch",
            ResultKind::LengthMismatch(_) => "length_mismatch",
            ResultKind::Utf8 { .. } => "utf8",
            ResultKind::DepthLimit => "depth",
            ResultKind::PanicAdd(_) => "panic_add",
            ResultKind::PanicSub(_) => "panic_sub",
            ResultKind::UnreachableTag(_) => "unreachable",
        }
    }

    #[test]
    fn saved_cases_match_result_class_and_deserializer_state() {
        let mut checked = 0;
        for line in CASES.lines().skip(1) {
            let f: Vec<_> = line.split('\t').collect();
            let input = if f[1] == "-" { vec![] } else { hex_bytes(f[1]) };
            let peek = if f[2] == "-" {
                None
            } else {
                let pair = f[2].trim_start_matches('(').trim_end_matches(')');
                let mut values = pair.split(',');
                Some((
                    number(values.next().unwrap()) as u8,
                    number(values.next().unwrap()) as u8,
                ))
            };
            let knob_text = f[5];
            let (result, rest) = if let Some(rest) = knob_text.strip_prefix("((ok,0x2a),") {
                (CalleeResult::Ok, rest)
            } else {
                (
                    CalleeResult::Err,
                    knob_text.strip_prefix("((err,5),").unwrap(),
                )
            };
            let mut parts = rest.trim_end_matches(')').split(',');
            let remaining_part = parts.next().unwrap();
            let depth_part = parts.next().unwrap();
            let remaining = if remaining_part == "-" {
                None
            } else {
                Some(number(remaining_part))
            };
            let depth_after = if depth_part == "-" {
                None
            } else {
                Some(number(depth_part) as u16)
            };
            let actual = deserialize_any(
                &input,
                peek,
                number(f[3]) as u16,
                f[4].parse().unwrap(),
                VisitorKnob {
                    result,
                    remaining,
                    depth_after,
                },
            );
            assert_eq!(
                expected_class(&actual.result),
                expected_class_text(f[6]),
                "result row {}: {:?}",
                f[0],
                actual.result
            );
            assert_eq!(render(&actual.result), f[6], "result payload row {}", f[0]);
            let state = f[8].trim_start_matches('(').trim_end_matches(')');
            let mut state_parts = state.split(',');
            let expected_pos = number(state_parts.next().unwrap()) as usize;
            let expected_peek = number(state_parts.next().unwrap()) != 0;
            let expected_depth = number(state_parts.next().unwrap()) as u16;
            assert_eq!(
                (actual.input_position, actual.peek_consumed, actual.depth),
                (expected_pos, expected_peek, expected_depth),
                "state row {}",
                f[0]
            );
            assert_eq!(f[9], "ok", "C1 verdict row {}", f[0]);
            checked += 1;
        }
        assert_eq!(checked, 7_925);
    }

    fn expected_class_text(result: &str) -> &str {
        result.trim_matches(['(', ')']).split(',').next().unwrap()
    }
}
