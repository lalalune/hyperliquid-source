use std::io::{self, Read, Write};

fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).unwrap();
    let mut output = io::BufWriter::new(io::stdout().lock());
    for line in input.lines() {
        let f: Vec<u32> = line.split('\t').map(|v| v.parse().unwrap()).collect();
        assert_eq!(f.len(), 6);
        let value =
            node115_gossip_reload::metadata_gate_opens([f[0], f[1], f[2]], [f[3], f[4], f[5]]);
        writeln!(output, "{}", u8::from(value)).unwrap();
    }
}
