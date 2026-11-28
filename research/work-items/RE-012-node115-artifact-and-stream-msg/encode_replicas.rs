use node_runtime::stream_msg::{Date, Time};
use node_runtime::{ReplicaStreamRecord, SharedStreamMsg};
use std::io::{self, Write};

fn main() -> io::Result<()> {
    let mut output = io::BufWriter::new(io::stdout().lock());
    let integer_edges = [
        0,
        1,
        127,
        128,
        255,
        256,
        65_535,
        65_536,
        u32::MAX as u64,
        u32::MAX as u64 + 1,
        u64::MAX,
    ];
    let bundle_counts = [0, 1, 15, 16, 255, 256, 65_535, 65_536];
    let fractions = [0, 123_000_000, 123_456_000, 123_456_789];
    for (i, height) in integer_edges.into_iter().enumerate() {
        for (j, count) in bundle_counts.into_iter().enumerate() {
            let bundle_values: &[&[u8]] = &[&[0x90], &[0x81, 0xa1, b'x', 0xc3], &[0xa1, b'q']];
            let bundles: Vec<_> = bundle_values.iter().copied().cycle().take(count).collect();
            let mut proposer = [0u8; 20];
            for (k, byte) in proposer.iter_mut().enumerate() {
                *byte = (17 * k + i + j) as u8;
            }
            let record = ReplicaStreamRecord {
                date: Date::new(2024, 60).unwrap(),
                time: Time::new(45_296, fractions[(i + j) % fractions.len()]).unwrap(),
                encoded_bundles: &bundles,
                round: integer_edges[(i + 1) % integer_edges.len()],
                parent_round: integer_edges[(i + 2) % integer_edges.len()],
                hardfork_version: integer_edges[(i + 3) % integer_edges.len()],
                hardfork_round: integer_edges[(i + 4) % integer_edges.len()],
                proposer,
                encoded_responses: (j % 2 == 1).then_some(&[0x91, 0x81, 0xa2, b'o', b'k', 0xc3]),
                height,
            };
            let message = SharedStreamMsg::from_replica_record(&record).unwrap();
            let shared = message.clone();
            assert_eq!(message.strong_count(), 2);
            assert!(std::ptr::eq(message.as_bytes(), shared.as_bytes()));
            output.write_all(&(message.as_bytes().len() as u32).to_le_bytes())?;
            output.write_all(message.as_bytes())?;
        }
    }
    output.flush()
}
