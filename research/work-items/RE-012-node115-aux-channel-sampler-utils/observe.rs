use node_runtime::GroupAndSeqSampler;
use std::io::{self, Read, Write};

fn main() -> io::Result<()> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    let mut output = io::BufWriter::new(io::stdout().lock());
    let mut groups = GroupAndSeqSampler::new();
    for row in input.chunks_exact(16) {
        let group = u64::from_le_bytes(row[..8].try_into().unwrap());
        let nanos = u64::from_le_bytes(row[8..].try_into().unwrap());
        let mut single = GroupAndSeqSampler::new();
        single.record_nanos(group, nanos);
        groups.record_nanos(group, nanos);
        let sample = single.stats(group).unwrap();
        let running = groups.stats(group).unwrap();
        for value in [
            sample.total_secs.to_bits(),
            running.count,
            running.total_secs.to_bits(),
            running.max_secs.to_bits(),
        ] {
            output.write_all(&value.to_le_bytes())?;
        }
    }
    assert_eq!(input.len() % 16, 0);
    output.flush()
}
