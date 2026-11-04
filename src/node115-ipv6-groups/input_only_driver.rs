use node115_ipv6_groups::read_groups;
use std::io::{self, Read, Write};
fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).unwrap();
    let mut output = io::BufWriter::new(io::stdout().lock());
    for line in input.lines() {
        let f: Vec<_> = line.split('\t').collect();
        assert_eq!(f.len(), 3);
        let cap: usize = f[0].parse().unwrap();
        let mode: u16 = f[1].parse().unwrap();
        assert!(cap <= 8 && mode <= 1 && f[2].len() % 2 == 0);
        let data: Vec<u8> = (0..f[2].len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&f[2][i..i + 2], 16).unwrap())
            .collect();
        let mut words = std::array::from_fn(|i| if mode == 1 { 0x5a00 + i as u16 } else { 0 });
        let mut cursor = data.as_slice();
        let result = read_groups(&mut cursor, &mut words, cap);
        write!(
            output,
            "{}\t{}\t{}\t{}",
            result.count,
            u8::from(result.ipv4_tail),
            data.len() - cursor.len(),
            cursor.len()
        )
        .unwrap();
        for word in words {
            write!(output, "\t{word}").unwrap();
        }
        writeln!(output).unwrap();
    }
}
