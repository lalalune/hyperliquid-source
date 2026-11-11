use node115_fee_active_scaling::{scale, Exit};
use std::io::{self, BufRead};
pub fn evaluate_line(line: &str) -> String {
    let mut fields = line.split('\t');
    let hex = fields.next().unwrap();
    assert_eq!(hex.len(), 240);
    let mut raw = [0; 120];
    for (i, byte) in raw.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
    }
    let seed = fields.next().unwrap().parse::<u8>().unwrap();
    assert!(fields.next().is_none());
    let observed = scale(&raw, seed);
    let kind = match observed.exit {
        Exit::Returned => "R",
        Exit::FirstDiagnostic => "A",
        Exit::InnerDiagnostic => "I",
        Exit::LastDiagnostic => "L",
    };
    let mut output = String::with_capacity(240);
    for byte in observed.output {
        match byte {
            Some(value) => output.push_str(&format!("{value:02x}")),
            None => output.push_str("??"),
        }
    }
    format!("[\"{kind}\",\"{output}\"]")
}
fn main() {
    for line in io::stdin().lock().lines() {
        println!("{}", evaluate_line(&line.unwrap()));
    }
}
