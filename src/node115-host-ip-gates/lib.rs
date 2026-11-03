//! Independently authored, digest-specific semantic projection. See evidence packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admission {
    BeforeParser,
    Reject,
    Collect,
}
pub fn admission(length: u64, parser_al: u8, remaining: u64) -> Admission {
    if length > 15 {
        Admission::BeforeParser
    } else if parser_al & 1 != 0 && remaining == 0 {
        Admission::Collect
    } else {
        Admission::Reject
    }
}
pub fn should_probe(override_word: u64) -> bool {
    override_word == (1u64 << 63)
}
/// Parse an IPv4 prefix, consuming only on success. No services or discovery.
pub fn read_ipv4(cursor: &mut &[u8]) -> Option<[u8; 4]> {
    let bytes = *cursor;
    let mut at = 0;
    let mut address = [0; 4];
    for (slot, octet) in address.iter_mut().enumerate() {
        let start = at;
        let mut value = 0u32;
        while let Some(&digit) = bytes.get(at) {
            if !digit.is_ascii_digit() {
                break;
            }
            // The native parser fails before accepting any fourth decimal digit.
            if at - start == 3 {
                return None;
            }
            value = value * 10 + u32::from(digit - b'0');
            at += 1;
        }
        if at == start || value > 255 || (at - start > 1 && bytes[start] == b'0') {
            return None;
        }
        *octet = value as u8;
        if slot != 3 {
            if bytes.get(at) != Some(&b'.') {
                return None;
            }
            at += 1;
        }
    }
    *cursor = &bytes[at..];
    Some(address)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn target_raw_boundaries() {
        for line in
            include_str!("../../research/work-items/RE-014-host-ip-gates-115/target-smoke.tsv")
                .lines()
        {
            let f: Vec<_> = line.split('\t').collect();
            if f[0] == "M" {
                let out = match admission(
                    f[1].parse().unwrap(),
                    f[2].parse().unwrap(),
                    f[3].parse().unwrap(),
                ) {
                    Admission::BeforeParser => "B",
                    Admission::Reject => "R",
                    Admission::Collect => "A",
                };
                assert_eq!(out, f[4]);
            } else {
                assert_eq!(
                    u8::from(should_probe(f[1].parse().unwrap())).to_string(),
                    f[2]
                );
            }
        }
    }
    #[test]
    fn target_parser_and_composition() {
        for line in
            include_str!("../../research/work-items/RE-014-host-ip-gates-115/parser-smoke.tsv")
                .lines()
        {
            let f: Vec<_> = line.split('\t').collect();
            let data: Vec<u8> = (0..f[1].len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&f[1][i..i + 2], 16).unwrap())
                .collect();
            if f[0] == "C" && data.len() > 15 {
                assert_eq!(f[2], "B");
                continue;
            }
            let mut cursor = data.as_slice();
            let result = read_ipv4(&mut cursor);
            let tag = if f[0] == "C" {
                if result.is_some() && cursor.is_empty() {
                    "A"
                } else {
                    "R"
                }
            } else if result.is_some() {
                "1"
            } else {
                "0"
            };
            let payload = result.map(u32::from_le_bytes).unwrap_or(0);
            assert_eq!(
                format!(
                    "{tag},{payload},{},{}",
                    data.len() - cursor.len(),
                    cursor.len()
                ),
                f[2]
            );
        }
    }
}
