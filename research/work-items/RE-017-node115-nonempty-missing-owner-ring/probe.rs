use node115_client_block_success::{ReplayPayload, decode_replay_payload_prefix};
use node115_rpc_flat_materializer::{RingView, Row, SearchResult};
use std::{env, fs};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn main() {
    let mut operands = env::args_os().skip(1);
    let wire = fs::read(operands.next().expect("verified Block wire")).unwrap();
    let ring =
        fs::read_to_string(operands.next().expect("verified physical ring fixture")).unwrap();
    let decoded = decode_replay_payload_prefix(&wire, 10_000_000);
    assert!(
        decoded.remaining.is_empty(),
        "wire must contain one complete record"
    );
    let ReplayPayload::Block { block, attachments } = decoded.result.unwrap() else {
        panic!("Block required");
    };
    assert!(
        attachments.is_none() && !block.header.hashes.is_empty(),
        "missing nonempty owner required"
    );

    let mut items = ring.split_whitespace();
    let head = items.next().unwrap().parse().unwrap();
    let live = items.next().unwrap().parse().unwrap();
    let mut rows = Vec::new();
    while let Some(text) = items.next() {
        assert_eq!(text.len(), 64, "full 32-byte key required");
        let key = std::array::from_fn(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap());
        let value = items.next().expect("opaque value").parse().unwrap();
        rows.push(Row { key, value });
    }
    let view = RingView::new(&rows, head, live).expect("ordinary live ring");
    let mut materialized = Vec::new();
    for (index, key) in block.header.hashes.iter().enumerate() {
        match view.search(key) {
            SearchResult::Found {
                logical_index,
                physical_index,
                value,
            } => {
                materialized.push(format!(
                    "{{\"position\":{index},\"key\":\"{}\",\"logical_index\":{logical_index},\"physical_index\":{physical_index},\"opaque_value\":{value}}}",
                    hex(key)
                ));
            }
            SearchResult::Missing { .. } => {
                println!(
                    "{{\"status\":\"missing\",\"position\":{index},\"key\":\"{}\"}}",
                    hex(key)
                );
                return;
            }
        }
    }
    println!(
        "{{\"status\":\"materialized\",\"rows\":[{}]}}",
        materialized.join(",")
    );
}
