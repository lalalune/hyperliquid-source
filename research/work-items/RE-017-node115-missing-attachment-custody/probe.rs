use node115_client_block_success::{ReplayPayload, decode_replay_payload_prefix};
use std::io::{self, Read};

fn main() -> io::Result<()> {
    let mut bytes = Vec::new();
    io::stdin().read_to_end(&mut bytes)?;
    let decoded = decode_replay_payload_prefix(&bytes, 10_000_000);
    assert!(decoded.remaining.is_empty());
    let ReplayPayload::Block { block, attachments } =
        decoded.result.expect("decoded replay payload")
    else {
        panic!("a Block is required");
    };
    println!(
        "{}",
        if attachments.is_some() {
            "present"
        } else {
            "absent"
        }
    );
    for key in block.header.hashes {
        println!(
            "0x{}",
            key.iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        );
    }
    Ok(())
}
