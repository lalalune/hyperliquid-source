use node115_abci_blake3::blake3_hash;
use std::error::Error;
use std::fmt::Write;

fn leaf(value: u64) -> String {
    let mut hex = String::from("0x");
    for byte in blake3_hash(&value.to_le_bytes()) {
        write!(hex, "{byte:02x}").expect("writing to String");
    }
    hex
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let [version, round, tx_index] = args.as_slice() else {
        return Err("usage: project HARDFORK_VERSION HARDFORK_ROUND TX_INDEX_OR_NONE".into());
    };
    let version = leaf(version.parse()?);
    let round = leaf(round.parse()?);
    let tx = if tx_index == "none" {
        format!("[[1,\"{}\"]]", leaf(0))
    } else {
        format!("[[0,\"{}\"],[1,\"{}\"]]", leaf(tx_index.parse()?), leaf(1))
    };
    println!("{{\"hardfork\":[[0,\"{version}\"],[1,\"{round}\"]],\"tx_index\":{tx}}}");
    Ok(())
}
