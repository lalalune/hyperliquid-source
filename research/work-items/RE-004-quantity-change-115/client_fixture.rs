fn evaluate_row(words: &[u64]) -> Result<String, &'static str> {
    if words.len() != 6 || words[0] > 2 || words[5] > 255 {
        return Err("point0..2, four u64 words and seed0..255 required");
    }
    let point = words[0];
    let old = words[1] as i64;
    let new = words[2] as i64;
    let seed = words[5] as u8;
    let notification = Notification {
        word: words[4],
        payload: std::array::from_fn(|i| seed.wrapping_add((i as u8).wrapping_mul(17))),
    };
    let observed = if point == 2 {
        post_lookup(old, new, words[3] as i64, notification)
    } else {
        entry(old, new, words[3], point == 1, notification)
    };
    let written = if observed.writes.is_empty() {
        "-".to_string()
    } else {
        observed
            .writes
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join(",")
    };
    let next = match observed.next {
        Boundary::Returned => "R".to_string(),
        Boundary::Lookup => "L".to_string(),
        Boundary::AbsoluteDiagnostic => "I".to_string(),
        Boundary::SubtractDiagnostic { pending } => format!("S:{}", pending as u64),
        Boundary::AddDiagnostic { pending } => format!("A:{}", pending as u64),
        Boundary::Notify {
            word,
            new_bits,
            payload,
        } => {
            let raw: String = payload.iter().map(|b| format!("{b:02x}")).collect();
            format!("N:{word}:{new_bits}:{raw}")
        }
    };
    let prefix = if point == 2 { 'T' } else { 'E' };
    Ok(format!("{prefix}:{}:{written}:{next}", observed.value))
}
