//! Input-only comparison adapter; request mode composes the selected caller's
//! three possible wrapper calls. It is not a network decoder or target ABI.
use hl_bincode_varint::{ReaderError, SliceDecoder, SliceError};

fn error(error: SliceError) -> (String, String) {
    match error {
        SliceError::LimitExceeded => ("limit".into(), "-".into()),
        SliceError::Reader(ReaderError::UnexpectedEnd { needed }) => {
            ("end".into(), needed.to_string())
        }
        SliceError::Reader(ReaderError::InvalidIntegerType {
            expected_code,
            found_code,
        }) => ("type".into(), format!("{expected_code}:{found_code}")),
    }
}

fn request(decoder: &mut SliceDecoder<'_>) -> Result<(String, String), SliceError> {
    let tag = decoder.read_u32()?;
    match tag {
        0 => {
            let first = decoder.read_u64()?;
            let second = decoder.read_u64()?;
            Ok(("pair".into(), format!("{first}:{second}")))
        }
        1 | 2 => Ok(("unit".into(), tag.to_string())),
        _ => Ok(("badtag".into(), tag.to_string())),
    }
}

pub fn run(line: &str) -> String {
    let fields: Vec<_> = line.split_whitespace().collect();
    let bytes: Vec<u8> = if fields[5] == "-" {
        Vec::new()
    } else {
        (0..fields[5].len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&fields[5][i..i + 2], 16).unwrap())
            .collect()
    };
    let mut decoder = SliceDecoder::from_state(
        &bytes,
        fields[2].parse().unwrap(),
        fields[3].parse().unwrap(),
        fields[4].parse().unwrap(),
    );
    let result = match fields[1] {
        "32" => decoder
            .read_u32()
            .map(|value| ("ok".to_owned(), value.to_string())),
        "64" => decoder
            .read_u64()
            .map(|value| ("ok".to_owned(), value.to_string())),
        "request" => request(&mut decoder),
        _ => panic!("unknown comparison operation"),
    };
    let (status, payload) = result.unwrap_or_else(error);
    let suffix = if decoder.remaining().is_empty() {
        "-".to_owned()
    } else {
        decoder
            .remaining()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    };
    format!(
        "{}\t{status}\t{payload}\t{}\t{}\t{suffix}",
        fields[0],
        bytes.len() - decoder.remaining().len(),
        decoder.charge()
    )
}
