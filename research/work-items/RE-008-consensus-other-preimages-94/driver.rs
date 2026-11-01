//! Input-only offline driver. No expected bytes, names, digests or lengths enter here.
use node94_consensus_admission::message_preimages::*;
use node94_consensus_admission::{
    BlockHash, Hardfork, Qc, QcVote, Round, SignatureBytes, ValidatorAddress,
};
use std::io::{self, BufRead};

struct Input<'a>(&'a [u8]);
impl Input<'_> {
    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], String> {
        let bytes = self.0.get(..N).ok_or("short input")?;
        let mut result = [0; N];
        result.copy_from_slice(bytes);
        self.0 = &self.0[N..];
        Ok(result)
    }
    fn byte(&mut self) -> Result<u8, String> {
        Ok(self.fixed::<1>()?[0])
    }
    fn word(&mut self) -> Result<u64, String> {
        Ok(u64::from_le_bytes(self.fixed()?))
    }
    fn small(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(self.fixed()?))
    }
    fn presence(&mut self) -> Result<bool, String> {
        match self.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err("bad option".into()),
        }
    }
    fn count(&mut self, width: usize) -> Result<usize, String> {
        let count = usize::try_from(self.small()?).map_err(|_| "count range")?;
        if count > self.0.len() / width {
            return Err("count exceeds input".into());
        }
        Ok(count)
    }
    fn map(&mut self) -> Result<Option<Vec<OrderedWordEntry>>, String> {
        if !self.presence()? {
            return Ok(None);
        }
        let count = self.count(28)?;
        let mut rows = Vec::with_capacity(count);
        for _ in 0..count {
            rows.push(OrderedWordEntry {
                address: ValidatorAddress(self.fixed()?),
                word: self.word()?,
            });
        }
        Ok(Some(rows))
    }
    fn set(&mut self) -> Result<Option<Vec<ValidatorAddress>>, String> {
        if !self.presence()? {
            return Ok(None);
        }
        let count = self.count(20)?;
        let mut rows = Vec::with_capacity(count);
        for _ in 0..count {
            rows.push(ValidatorAddress(self.fixed()?));
        }
        Ok(Some(rows))
    }
    fn summary(&mut self) -> Result<ConsensusSummary, String> {
        Ok(ConsensusSummary {
            block_hash: BlockHash(self.fixed()?),
            first: self.word()?,
            second: self.word()?,
        })
    }
}

fn process(bytes: &[u8]) -> Result<(usize, Vec<u8>, [u8; 32]), String> {
    let mut input = Input(bytes);
    let variant = input.byte()?;
    let signer = ValidatorAddress(input.fixed()?);
    let result = match variant {
        2 => {
            let round = Round(input.word()?);
            let version = input.word()?;
            let start_round = Round(input.word()?);
            let qc_round = Round(input.word()?);
            let block_hash = BlockHash(input.fixed()?);
            let count = input.count(92)?;
            let mut votes = Vec::with_capacity(count);
            for _ in 0..count {
                votes.push(QcVote {
                    signer: ValidatorAddress(input.fixed()?),
                    signature: SignatureBytes(input.fixed()?),
                });
            }
            let qc = Qc {
                votes,
                hardfork: Hardfork {
                    version,
                    start_round,
                },
                round: qc_round,
                block_hash,
            };
            (
                timeout_preimage_len(&qc, round),
                timeout_preimage(&qc, round, signer),
                timeout_digest(&qc, round, signer),
            )
        }
        3 => {
            let round = Round(input.word()?);
            let random = input.small()?;
            let snapshot_present = input.presence()?;
            let (stakes, jailed, evm_word, summaries) = if snapshot_present {
                let stakes = input.map()?;
                let jailed = input.set()?;
                let evm_word = input.word()?;
                let summaries = if input.presence()? {
                    Some([input.summary()?, input.summary()?, input.summary()?])
                } else {
                    None
                };
                (stakes, jailed, evm_word, summaries)
            } else {
                (None, None, 0, None)
            };
            let peers = input.map()?;
            let snapshot = snapshot_present.then_some(HeartbeatSnapshot {
                stakes: stakes.as_deref(),
                jailed: jailed.as_deref(),
                evm_word,
                summaries: summaries.as_ref(),
            });
            let message = HeartbeatMessage {
                signer,
                round,
                random,
                snapshot,
                peers: peers.as_deref(),
            };
            (
                heartbeat_preimage_len(&message),
                heartbeat_preimage(&message),
                heartbeat_digest(&message),
            )
        }
        4 => {
            let random = input.small()?;
            let round = Round(input.word()?);
            (
                Ok(acknowledgement_preimage_len(random, round)),
                acknowledgement_preimage(signer, random, round),
                acknowledgement_digest(signer, random, round),
            )
        }
        _ => return Err("bad variant".into()),
    };
    if !input.0.is_empty() {
        return Err("trailing input".into());
    }
    let (length, preimage, digest) = result;
    let length = length.map_err(|x| x.to_string())?;
    let preimage = preimage.map_err(|x| x.to_string())?;
    let digest = digest.map_err(|x| x.to_string())?;
    if length != preimage.len() {
        return Err("length disagrees".into());
    }
    Ok((length, preimage, digest))
}

fn unhex(text: &str) -> Result<Vec<u8>, String> {
    if text.len() % 2 != 0 || !text.is_ascii() {
        return Err("bad hex".into());
    }
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).map_err(|_| "bad hex".into()))
        .collect()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn main() {
    for line in io::stdin().lock().lines() {
        let result = line
            .map_err(|x| x.to_string())
            .and_then(|x| unhex(&x))
            .and_then(|x| process(&x));
        match result {
            Ok((length, preimage, digest)) => {
                println!("{length}\t{}\t{}", hex(&preimage), hex(&digest))
            }
            Err(_) => println!("ERR"),
        }
    }
}
