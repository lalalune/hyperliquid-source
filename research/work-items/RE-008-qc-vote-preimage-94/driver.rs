// Offline value driver for the real component. No target-byte inputs or execution.
use node94_consensus_admission::{
    qc_vote_digest, qc_vote_preimage, BlockHash, Hardfork, Qc, Round, ValidatorAddress,
};
use std::io::{self, BufRead};

fn bytes<const N: usize>(s: &str) -> [u8; N] {
    assert_eq!(s.len(), N * 2);
    std::array::from_fn(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
}
fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}
fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let f: Vec<_> = line.split('\t').collect();
        assert_eq!(f.len(), 6);
        let qc = Qc {
            votes: vec![],
            hardfork: Hardfork {
                version: f[1].parse().unwrap(),
                start_round: Round(f[2].parse().unwrap()),
            },
            round: Round(f[3].parse().unwrap()),
            block_hash: BlockHash(bytes(f[5])),
        };
        let signer = ValidatorAddress(bytes(f[4]));
        println!(
            "{}\t{}\t{}",
            f[0],
            hex(&qc_vote_preimage(&qc, signer)),
            hex(&qc_vote_digest(&qc, signer))
        );
    }
}
