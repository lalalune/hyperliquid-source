//! Independently authored bounded group reader; no full IPv6/parser ABI claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Groups {
    pub count: usize,
    pub ipv4_tail: bool,
}
fn read_hex(cursor: &mut &[u8]) -> Option<u16> {
    let bytes = *cursor;
    let mut n = 0;
    let mut value = 0u16;
    for &byte in bytes {
        let digit = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => break,
        };
        if n == 4 {
            return None;
        }
        value = value * 16 + u16::from(digit);
        n += 1;
    }
    if n == 0 {
        return None;
    }
    *cursor = &bytes[n..];
    Some(value)
}
/// Read at most capacity groups, preserving unused output and failed separators.
pub fn read_groups(cursor: &mut &[u8], out: &mut [u16; 8], capacity: usize) -> Groups {
    assert!(capacity <= 8, "own API precondition");
    let mut count = 0;
    while count < capacity {
        let checkpoint = *cursor;
        if count != 0 {
            if cursor.first() != Some(&b':') {
                break;
            }
            *cursor = &cursor[1..];
        }
        if capacity - count >= 2 {
            if let Some(ip) = read_ipv4(cursor) {
                out[count] = u16::from_be_bytes([ip[0], ip[1]]);
                out[count + 1] = u16::from_be_bytes([ip[2], ip[3]]);
                return Groups {
                    count: count + 2,
                    ipv4_tail: true,
                };
            }
        }
        if let Some(word) = read_hex(cursor) {
            out[count] = word;
            count += 1;
        } else {
            *cursor = checkpoint;
            break;
        }
    }
    Groups {
        count,
        ipv4_tail: false,
    }
}

// Project-MIT helper reused from own PR2334 at eb0b4600; not new recovery.
fn read_ipv4(cursor: &mut &[u8]) -> Option<[u8; 4]> {
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
    fn native_group_and_memory_effect_rows() {
        for line in
            include_str!("../../research/work-items/RE-012-ipv6-groups-115/target-smoke.tsv")
                .lines()
        {
            let f: Vec<_> = line.split('\t').collect();
            assert_eq!(f.len(), 15);
            let cap: usize = f[0].parse().unwrap();
            let mode: u16 = f[1].parse().unwrap();
            let data: Vec<u8> = (0..f[2].len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&f[2][i..i + 2], 16).unwrap())
                .collect();
            let mut out = std::array::from_fn(|i| if mode == 1 { 0x5a00 + i as u16 } else { 0 });
            let mut cursor = data.as_slice();
            let result = read_groups(&mut cursor, &mut out, cap);
            let mut actual = vec![
                result.count.to_string(),
                u8::from(result.ipv4_tail).to_string(),
                (data.len() - cursor.len()).to_string(),
                cursor.len().to_string(),
            ];
            actual.extend(out.map(|x| x.to_string()));
            assert_eq!(actual.join("\t"), f[3..].join("\t"));
        }
    }
}
