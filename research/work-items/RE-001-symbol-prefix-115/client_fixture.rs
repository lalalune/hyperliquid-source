fn decode_hex(text: &str) -> Result<Vec<u8>, &'static str> {
    if !text.len().is_multiple_of(2) {
        return Err("odd hex length");
    }
    fn nibble(byte: u8) -> Result<u8, &'static str> {
        match byte {
            b'0'..=b'9' => Ok(byte - b'0'),
            b'a'..=b'f' => Ok(byte - b'a' + 10),
            _ => Err("lowercase ASCII hex required"),
        }
    }
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| Ok((nibble(pair[0])? << 4) | nibble(pair[1])?))
        .collect()
}

fn render(value: PrefixObservation) -> String {
    match value {
        PrefixObservation::Rejected => "R".to_string(),
        PrefixObservation::Direct(id) => format!("D:{id}"),
        PrefixObservation::NeedsAllocation(request) => {
            let encoded: String = request
                .decimal_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            format!("A:{}:{encoded}", request.parsed)
        }
    }
}
