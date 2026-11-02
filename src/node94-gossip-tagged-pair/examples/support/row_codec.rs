//! Input-only fixed-wire adapter; expected files never enter this module.
use node94_gossip_tagged_pair::{Budget, Decoded, Failure, ScalarFault, decode_tagged_pair};
use std::io;

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn identifier(text: &str) -> io::Result<&str> {
    if text.is_empty()
        || text.len() > 64
        || !text.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(invalid("invalid case identifier"));
    }
    Ok(text)
}

fn decimal(text: &str) -> io::Result<u64> {
    if text.is_empty()
        || text.len() > 20
        || (text.len() > 1 && text.starts_with('0'))
        || !text.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(invalid("expected canonical decimal u64"));
    }
    text.parse().map_err(|_| invalid("decimal exceeds u64"))
}

fn unhex(text: &str) -> io::Result<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return Err(invalid("odd hexadecimal length"));
    }
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |byte| match byte {
                b'0'..=b'9' => Some(byte - b'0'),
                b'a'..=b'f' => Some(byte - b'a' + 10),
                _ => None,
            };
            match (digit(pair[0]), digit(pair[1])) {
                (Some(high), Some(low)) => Ok(high * 16 + low),
                _ => Err(invalid("expected lowercase hexadecimal bytes")),
            }
        })
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("formatting into owned String");
    }
    output
}

fn number<T: std::fmt::Display>(value: Option<T>) -> String {
    value.map_or_else(|| "null".to_owned(), |n| n.to_string())
}

pub fn row(line: &str) -> io::Result<String> {
    let fields: Vec<_> = line.split('\t').collect();
    if fields.len() != 5 { return Err(invalid("expected id,mode,counter,limit,wire_hex")); }
    let id = identifier(fields[0])?;
    let mut budget = Budget { mode_word: decimal(fields[1])?, counter: decimal(fields[2])?, limit: decimal(fields[3])? };
    let wire = unhex(fields[4])?;
    let mut input = wire.as_slice();
    let outcome = decode_tagged_pair(&mut input, &mut budget);
    let mut option_tag = None;
    let mut first = None;
    let mut second = None;
    let mut needed = None;
    let mut expected = None;
    let mut found = None;
    let mut type_name = "null".to_owned();
    let mut allowed_tags = "null".to_owned();
    let tag;
    let phase;
    match outcome.result {
        Ok(Decoded::TagZero) => { tag = 18; phase = "none"; option_tag = Some(0); }
        Ok(Decoded::TagOne { first: a, second: b }) => {
            tag = 18; phase = "some"; option_tag = Some(1); first = Some(a); second = Some(b);
        }
        Err(problem) => {
            let scalar = match problem {
                Failure::Selector(error) => { phase = "selector_error"; Some(error) }
                Failure::First(error) => { phase = "first_error"; Some(error) }
                Failure::Second(error) => { phase = "second_error"; Some(error) }
                Failure::InvalidSelector { found: value } => {
                    phase = "selector_error";
                    found = Some(value);
                    let literal = problem.observed_type_name().expect("production diagnostic");
                    type_name = format!("\"{literal}\"");
                    allowed_tags = format!("[{}]", problem.allowed_selectors().expect("production legal tags").iter().map(u8::to_string).collect::<Vec<_>>().join(","));
                    None
                }
            };
            tag = match scalar {
                None => 5,
                Some(ScalarFault::Budget) => 2,
                Some(ScalarFault::Need { additional }) => { needed = Some(additional); 0 }
                Some(ScalarFault::Type { expected: e, found: f }) => { expected = Some(e); found = Some(f); 3 }
            };
        }
    }
    let stores = outcome.counter_stores.as_slice().iter().map(u64::to_string).collect::<Vec<_>>().join(",");
    Ok(format!(
        "{{\"allowed_tags\":{allowed_tags},\"consumed\":{},\"counter_after\":{},\"counter_writes\":[{stores}],\"expected\":{},\"first\":{},\"found\":{},\"id\":\"{id}\",\"needed\":{},\"option_tag\":{},\"phase\":\"{phase}\",\"remaining\":{},\"second\":{},\"tag\":{tag},\"tail_hex\":\"{}\",\"type_name\":{type_name}}}",
        wire.len() - input.len(), budget.counter, number(expected), number(first), number(found), number(needed), number(option_tag), input.len(), number(second), hex(input)
    ))
}
