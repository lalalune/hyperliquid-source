// Input-only adapter; no target expectations or alternate conversion formula.
fn adapt(input: &str) -> std::string::String {
    use std::fmt::Write as _;
    let fields: std::vec::Vec<_> = input.split('\t').collect();
    assert_eq!(fields.len(), 5);
    let first: std::vec::Vec<u64> = if fields[2] == "-" {
        std::vec::Vec::new()
    } else {
        fields[2].split(',').map(|s| s.parse().unwrap()).collect()
    };
    let decimals: std::vec::Vec<u8> = if fields[3] == "-" {
        std::vec::Vec::new()
    } else {
        assert_eq!(fields[3].len() % 2, 0);
        (0..fields[3].len()).step_by(2)
            .map(|i| u8::from_str_radix(&fields[3][i..i + 2], 16).unwrap()).collect()
    };
    let seed: u8 = fields[4].parse().unwrap();
    let mut out = [0_u8; 16];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = seed.wrapping_add((i as u8).wrapping_mul(17));
    }
    match convert(fields[0].parse().unwrap(), fields[1].parse().unwrap(), &first, &decimals, &mut out) {
        Observation::FirstIndexBoundary => std::string::String::from("A"),
        Observation::SecondIndexBoundary => std::string::String::from("B"),
        Observation::Returned => {
            let mut text = std::string::String::from("O:");
            for byte in out { std::write!(text, "{byte:02x}").unwrap(); }
            text
        }
    }
}
