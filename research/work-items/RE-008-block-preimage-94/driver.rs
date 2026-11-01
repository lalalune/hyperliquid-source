//! Own input-only offline client: opaque ID and fixed-width input frame only.
//! No expected bytes, lengths, semantic names, digests or fixture paths enter.
use node94_consensus_admission::block_preimage::{
    block_digest, block_preimage, block_preimage_len, PackedBlockTime,
};
use node94_consensus_admission::{
    BlockHash, Hardfork, Qc, QcVote, Round, SignatureBytes, SignedBlock, Tc, TimeoutVote,
    TransactionHash, ValidatorAddress,
};
use std::io::{self, BufRead};

struct Input<'a>(&'a [u8]);
impl Input<'_> {
    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], String> {
        let bytes = self.0.get(..N).ok_or("short input")?;
        let mut output = [0; N];
        output.copy_from_slice(bytes);
        self.0 = &self.0[N..];
        Ok(output)
    }
    fn word(&mut self) -> Result<u64, String> {
        Ok(u64::from_le_bytes(self.fixed()?))
    }
    fn small(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(self.fixed()?))
    }
    fn count(&mut self, minimum_width: usize) -> Result<usize, String> {
        let n = usize::try_from(self.small()?).map_err(|_| "count range")?;
        if n > self.0.len() / minimum_width {
            return Err("count exceeds remaining frame".into());
        }
        Ok(n)
    }
    fn qc(&mut self) -> Result<Qc, String> {
        let version = self.word()?;
        let start_round = Round(self.word()?);
        let round = Round(self.word()?);
        let block_hash = BlockHash(self.fixed()?);
        let n = self.count(92)?;
        let mut votes = Vec::with_capacity(n);
        for _ in 0..n {
            votes.push(QcVote {
                signer: ValidatorAddress(self.fixed()?),
                signature: SignatureBytes(self.fixed()?),
            });
        }
        Ok(Qc {
            votes,
            hardfork: Hardfork {
                version,
                start_round,
            },
            round,
            block_hash,
        })
    }
}

fn process(frame: &[u8]) -> Result<(usize, Vec<u8>, [u8; 32]), String> {
    let mut input = Input(frame);
    let proposer = ValidatorAddress(input.fixed()?);
    let round = Round(input.word()?);
    let time = PackedBlockTime {
        packed_date: i32::from_le_bytes(input.fixed()?),
        seconds: input.small()?,
        nanoseconds: input.small()?,
    };
    let n = input.count(32)?;
    let mut transaction_hashes = Vec::with_capacity(n);
    for _ in 0..n {
        transaction_hashes.push(TransactionHash(input.fixed()?));
    }
    let qc = input.qc()?;
    let tc = match input.fixed::<1>()?[0] {
        0 => None,
        1 => {
            let round = Round(input.word()?);
            let n = input.count(160)?;
            let mut votes = Vec::with_capacity(n);
            for _ in 0..n {
                // Protocol input puts signature after signer/round, unlike output.
                let signer = ValidatorAddress(input.fixed()?);
                let round = Round(input.word()?);
                let signature = SignatureBytes(input.fixed()?);
                let qc = input.qc()?;
                votes.push(TimeoutVote {
                    qc,
                    round,
                    signer,
                    signature,
                });
            }
            Some(Tc { votes, round })
        }
        _ => return Err("invalid option".into()),
    };
    let signature = SignatureBytes(input.fixed()?);
    if !input.0.is_empty() {
        return Err("trailing input".into());
    }
    let block = SignedBlock {
        transaction_hashes,
        qc,
        tc,
        round,
        proposer,
        signature,
    };
    let length = block_preimage_len(&block, time).map_err(|x| x.to_string())?;
    let preimage = block_preimage(&block, time).map_err(|x| x.to_string())?;
    let digest = block_digest(&block, time).map_err(|x| x.to_string())?;
    if length != preimage.len() {
        return Err("length disagrees".into());
    }
    Ok((length, preimage, digest))
}

fn unhex(text: &str) -> Result<Vec<u8>, String> {
    if text.len() % 2 != 0 || !text.is_ascii() {
        return Err("invalid hex".into());
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).map_err(|_| "invalid hex".into()))
        .collect()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn main() {
    for line in io::stdin().lock().lines() {
        let result = line.map_err(|x| x.to_string()).and_then(|line| {
            let (id, frame) = line.split_once('\t').ok_or("missing frame")?;
            if id.len() != 7 || !id.starts_with('C') || !id[1..].bytes().all(|b| b.is_ascii_digit())
            {
                return Err("invalid opaque ID".into());
            }
            let (length, preimage, digest) = process(&unhex(frame)?)?;
            Ok(format!(
                "{id}\t{length}\t{}\t{}",
                hex(&preimage),
                hex(&digest)
            ))
        });
        match result {
            Ok(text) => println!("{text}"),
            Err(_) => println!("ERR"),
        }
    }
}
