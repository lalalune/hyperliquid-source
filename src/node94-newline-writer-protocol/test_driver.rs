//! Test/standalone-harness stimulus decoding and observable request recording.
//! Not linked into the no_std production library. No expectation is read here.
use std::cell::Cell;
use std::format;
use std::string::String;
use std::vec::Vec;

type Proxy<'a> = dyn FnMut(&[u8], &Cell<u8>) -> u8 + 'a;

fn decode_hex(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0, "hex input must have complete bytes");
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = core::str::from_utf8(pair).expect("ASCII hex");
            u8::from_str_radix(text, 16).expect("hex byte")
        })
        .collect()
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut text = String::new();
    for byte in bytes {
        text.push_str(&format!("{byte:02x}"));
    }
    text
}

fn action(text: &str) -> (u8, Option<u8>) {
    let (result, mutation) = text.split_once(':').expect("return:mutation");
    let result = result.parse().expect("callback return byte");
    let mutation = if mutation == "-" {
        None
    } else {
        Some(mutation.parse().expect("callback flag byte"))
    };
    (result, mutation)
}

/// Read only one stimulus: id|inputhex|initialflag|actions|defaultaction.
/// A missing indexed action uses the explicit normal default, so additional
/// requests are observed instead of being turned into harness indexing panics.
pub fn transcript<F>(stimulus: &str, implementation: F) -> String
where
    F: FnOnce(&[u8], &Cell<u8>, &mut Proxy<'_>) -> u8,
{
    let fields: Vec<_> = stimulus.split('|').collect();
    assert_eq!(fields.len(), 5, "five input-only fields");
    let input = decode_hex(fields[1]);
    let flag = Cell::new(fields[2].parse().expect("initial flag byte"));
    let actions: Vec<_> = if fields[3].is_empty() {
        Vec::new()
    } else {
        fields[3].split(',').map(action).collect()
    };
    let default = action(fields[4]);
    let mut requests = Vec::new();
    let mut writer = |bytes: &[u8], flag: &Cell<u8>| {
        let index = requests.len();
        let before = flag.get();
        let (result, mutation) = actions.get(index).copied().unwrap_or(default);
        if let Some(value) = mutation {
            flag.set(value);
        }
        let mutation = match mutation {
            Some(value) => format!("{value}"),
            None => String::from("-"),
        };
        requests.push(format!("{index}:{}:{before}:{result}:{mutation}", encode_hex(bytes)));
        result
    };
    let status = implementation(&input, &flag, &mut writer);
    format!("{};{};{};{};{}", fields[0], status, flag.get(), requests.len(), requests.join(","))
}
