use node115_host_ip_gates::{admission, read_ipv4, should_probe, Admission};
use std::io::{self, Read, Write};
fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).unwrap();
    let mut output = io::BufWriter::new(io::stdout().lock());
    for line in input.lines() {
        let f: Vec<_> = line.split('\t').collect();
        match f[0] {
            "M" => {
                assert_eq!(f.len(), 4);
                let answer = match admission(
                    f[1].parse().unwrap(),
                    f[2].parse().unwrap(),
                    f[3].parse().unwrap(),
                ) {
                    Admission::BeforeParser => "B",
                    Admission::Reject => "R",
                    Admission::Collect => "A",
                };
                writeln!(output, "{answer}").unwrap();
            }
            "O" => {
                assert_eq!(f.len(), 2);
                writeln!(output, "{}", u8::from(should_probe(f[1].parse().unwrap()))).unwrap();
            }
            "P" | "C" => {
                assert_eq!(f.len(), 2);
                assert_eq!(f[1].len() % 2, 0);
                let data: Vec<u8> = (0..f[1].len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&f[1][i..i + 2], 16).unwrap())
                    .collect();
                if f[0] == "C" && admission(data.len() as u64, 0, 0) == Admission::BeforeParser {
                    writeln!(output, "B").unwrap();
                    continue;
                }
                let mut cursor = data.as_slice();
                let result = read_ipv4(&mut cursor);
                let route = if f[0] == "C" {
                    match admission(
                        data.len() as u64,
                        u8::from(result.is_some()),
                        cursor.len() as u64,
                    ) {
                        Admission::Collect => "A",
                        Admission::Reject => "R",
                        Admission::BeforeParser => unreachable!(),
                    }
                } else if result.is_some() {
                    "1"
                } else {
                    "0"
                };
                let payload = result.map(u32::from_le_bytes).unwrap_or(0);
                writeln!(
                    output,
                    "{route},{payload},{},{}",
                    data.len() - cursor.len(),
                    cursor.len()
                )
                .unwrap();
            }
            _ => panic!("unknown operation"),
        }
    }
}
