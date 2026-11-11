use node115_tcp_compression_plan::{Frame, Plan, plan};
use std::io::{self, BufRead, Write};
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn shown(frame: Frame) -> String {
    format!("{}:{}", frame.selected_len, hex(&frame.header))
}
fn main() {
    let mut out = io::BufWriter::new(io::stdout().lock());
    for line in io::stdin().lock().lines() {
        let row = line.unwrap();
        let values: Vec<u64> = row.split_whitespace().map(|v| v.parse().unwrap()).collect();
        let result = match plan(values[0], u32::try_from(values[1]).unwrap()) {
            Err(e) => format!("E:{e:?}"),
            Ok(Plan::Raw(f)) => format!("R:{}", shown(f)),
            Ok(Plan::Compress(p)) => {
                let prefix = format!(
                    "C:{}:{}:{}:{}",
                    p.allocation_bytes(),
                    p.sink_capacity(),
                    p.scratch_bytes(),
                    hex(&p.inner_prefix())
                );
                match p.finish(values[2], values[3]) {
                    Ok(f) => format!("{prefix}|F:{}", shown(f)),
                    Err(e) => format!("{prefix}|E:{e:?}"),
                }
            }
        };
        writeln!(out, "{result}").unwrap();
    }
}
