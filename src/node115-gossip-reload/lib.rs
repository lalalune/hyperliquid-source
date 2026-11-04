//! Raw metadata comparison at the node115 gossip reload parser handoff.
//! This is a research API, not the original object's memory or return ABI.
#![no_std]
#![forbid(unsafe_code)]

/// Strict lexicographic comparison with a signed first dword only.
/// The opaque predicate and metadata helper must already have returned normally.
/// The parser, ownership transfer, error carrier, clock and filesystem are excluded.
/// Reuses the project's MIT metadata policy at 5491d673, newly bound to node115.
pub fn metadata_gate_opens(new: [u32; 3], cached: [u32; 3]) -> bool {
    let normalize = |v: [u32; 3]| (v[0] as i32, v[1], v[2]);
    normalize(new) > normalize(cached)
}

#[cfg(test)]
extern crate std;
#[cfg(test)]
mod tests {
    use super::metadata_gate_opens;
    use std::vec::Vec;

    #[test]
    fn frozen_native_rows() {
        for line in
            include_str!("../../research/work-items/RE-014-gossip-reload-115/target-smoke.tsv")
                .lines()
        {
            let f: Vec<u32> = line.split('\t').map(|v| v.parse().unwrap()).collect();
            assert_eq!(
                u32::from(metadata_gate_opens([f[0], f[1], f[2]], [f[3], f[4], f[5]])),
                f[6],
                "{line}"
            );
        }
    }
}
