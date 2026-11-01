//! Input-only client. Frozen expectations remain exclusively in the parent.
use node94_action_signable::keccak256;
use node94_consensus_admission::*;
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, BufRead, Write};

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], String> {
        let end = self.offset.checked_add(count).ok_or("span overflow")?;
        let bytes = self.bytes.get(self.offset..end).ok_or("truncated frame")?;
        self.offset = end;
        Ok(bytes)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], String> {
        self.take(N)?.try_into().map_err(|_| "fixed field".into())
    }
    fn byte(&mut self) -> Result<u8, String> {
        Ok(self.array::<1>()?[0])
    }
    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_le_bytes(self.array()?))
    }
    fn count(&mut self, width: usize) -> Result<usize, String> {
        let count = self.u32()? as usize;
        if count > (self.bytes.len() - self.offset) / width {
            return Err("count exceeds remaining frame".into());
        }
        Ok(count)
    }
    fn time(&mut self) -> Result<ClientBlockTime, String> {
        Ok(ClientBlockTime([self.u32()?, self.u32()?, self.u32()?]))
    }
    fn option(&mut self) -> Result<bool, String> {
        match self.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err("invalid option".into()),
        }
    }
    fn qc(&mut self) -> Result<Qc, String> {
        let hardfork = Hardfork {
            version: self.u64()?,
            start_round: Round(self.u64()?),
        };
        let round = Round(self.u64()?);
        let block_hash = BlockHash(self.array()?);
        let count = self.count(92)?;
        let mut votes = Vec::new();
        for _ in 0..count {
            votes.push(QcVote {
                signer: ValidatorAddress(self.array()?),
                signature: SignatureBytes(self.array()?),
            });
        }
        Ok(Qc {
            hardfork,
            round,
            block_hash,
            votes,
        })
    }
    fn tc(&mut self) -> Result<Tc, String> {
        let round = Round(self.u64()?);
        let count = self.count(160)?; // QC minimum60 + round8 + signer20 + signature72.
        let mut votes = Vec::new();
        for _ in 0..count {
            votes.push(TimeoutVote {
                qc: self.qc()?,
                round: Round(self.u64()?),
                signer: ValidatorAddress(self.array()?),
                signature: SignatureBytes(self.array()?),
            });
        }
        Ok(Tc { round, votes })
    }
    fn block(&mut self) -> Result<TimedSignedBlock, String> {
        let round = Round(self.u64()?);
        let proposer = ValidatorAddress(self.array()?);
        let time = self.time()?;
        let count = self.count(32)?;
        let mut transaction_hashes = Vec::new();
        for _ in 0..count {
            transaction_hashes.push(TransactionHash(self.array()?));
        }
        let qc = self.qc()?;
        let tc = if self.option()? {
            Some(self.tc()?)
        } else {
            None
        };
        let signature = SignatureBytes(self.array()?);
        Ok(TimedSignedBlock {
            block: SignedBlock {
                transaction_hashes,
                qc,
                tc,
                round,
                proposer,
                signature,
            },
            time,
        })
    }
    fn item(&mut self) -> Result<ClientBlock, String> {
        let signed = self.block()?;
        let count = self.count(36)?;
        let mut transactions = Vec::new();
        for _ in 0..count {
            let hash = TransactionHash(self.array()?);
            let len = self.count(1)?;
            transactions.push(ClientTransaction {
                hash,
                bytes: self.take(len)?.to_vec(),
            });
        }
        let copied_time = self.time()?;
        let proof = if self.option()? {
            Some(ClientCommitProof {
                child: self.block()?,
                qc: self.qc()?,
            })
        } else {
            None
        };
        Ok(ClientBlock {
            signed,
            transactions,
            copied_time,
            proof,
        })
    }
    fn items(&mut self) -> Result<Vec<ClientBlock>, String> {
        let count = self.count(194)?; // Minimum block177 + tx count4 + copied time12 + option1.
        let mut items = Vec::new();
        for _ in 0..count {
            items.push(self.item()?);
        }
        Ok(items)
    }
    fn history(&mut self) -> Result<StakeHistory, String> {
        let base_round = Round(self.u64()?);
        let hardfork = Hardfork {
            version: self.u64()?,
            start_round: Round(self.u64()?),
        };
        let estimated_valid_until = Round(self.u64()?);
        let count = self.count(12)?;
        let mut snapshots = BTreeMap::new();
        let mut previous = None;
        for _ in 0..count {
            let round = Round(self.u64()?);
            if previous.is_some_and(|p| p >= round) {
                return Err("history keys not ordered".into());
            }
            previous = Some(round);
            let count = self.count(28)?;
            let mut stakes = BTreeMap::new();
            let mut previous_address = None;
            for _ in 0..count {
                let address = ValidatorAddress(self.array()?);
                if previous_address.is_some_and(|p| p >= address) {
                    return Err("stake keys not ordered".into());
                }
                previous_address = Some(address);
                stakes.insert(address, self.u64()?);
            }
            snapshots.insert(round, StakeSnapshot { stakes });
        }
        Ok(StakeHistory {
            base_round,
            hardfork,
            estimated_valid_until,
            snapshots,
        })
    }
}

fn count(out: &mut Vec<u8>, value: usize) {
    // Every decoded collection fits a u32; aggregate counts are admitted below.
    out.extend_from_slice(
        &u32::try_from(value)
            .expect("admitted frame count")
            .to_le_bytes(),
    );
}
fn word(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}
fn time_bytes(out: &mut Vec<u8>, time: ClientBlockTime) {
    for word in time.0 {
        out.extend_from_slice(&word.to_le_bytes());
    }
}
fn qc_scalar(out: &mut Vec<u8>, qc: &Qc) {
    word(out, qc.hardfork.version);
    word(out, qc.hardfork.start_round.0);
    word(out, qc.round.0);
    out.extend_from_slice(&qc.block_hash.0);
}
fn qc_bytes(out: &mut Vec<u8>, qc: &Qc) {
    qc_scalar(out, qc);
    count(out, qc.votes.len());
    for vote in &qc.votes {
        out.extend_from_slice(&vote.signer.0);
        out.extend_from_slice(&vote.signature.0);
    }
}
fn tc_bytes(out: &mut Vec<u8>, tc: &Tc) {
    word(out, tc.round.0);
    count(out, tc.votes.len());
    for vote in &tc.votes {
        qc_bytes(out, &vote.qc);
        word(out, vote.round.0);
        out.extend_from_slice(&vote.signer.0);
        out.extend_from_slice(&vote.signature.0);
    }
}
fn unsigned_bytes(block: &TimedSignedBlock) -> Vec<u8> {
    let mut out = Vec::new();
    let b = &block.block;
    word(&mut out, b.round.0);
    out.extend_from_slice(&b.proposer.0);
    time_bytes(&mut out, block.time);
    count(&mut out, b.transaction_hashes.len());
    for hash in &b.transaction_hashes {
        out.extend_from_slice(&hash.0);
    }
    qc_bytes(&mut out, &b.qc);
    out.push(u8::from(b.tc.is_some()));
    if let Some(tc) = &b.tc {
        tc_bytes(&mut out, tc);
    }
    out
}
fn block_bytes(out: &mut Vec<u8>, block: &TimedSignedBlock) {
    out.extend_from_slice(&unsigned_bytes(block));
    out.extend_from_slice(&block.block.signature.0);
}
fn item_bytes(item: &ClientBlock) -> Vec<u8> {
    let mut out = Vec::new();
    block_bytes(&mut out, &item.signed);
    count(&mut out, item.transactions.len());
    for tx in &item.transactions {
        out.extend_from_slice(&tx.hash.0);
        count(&mut out, tx.bytes.len());
        out.extend_from_slice(&tx.bytes);
    }
    time_bytes(&mut out, item.copied_time);
    out.push(u8::from(item.proof.is_some()));
    if let Some(proof) = &item.proof {
        block_bytes(&mut out, &proof.child);
        qc_bytes(&mut out, &proof.qc);
    }
    out
}
fn fingerprints(out: &mut Vec<u8>, items: &[ClientBlock]) {
    count(out, items.len());
    for item in items {
        out.extend_from_slice(&keccak256(&item_bytes(item)));
    }
}

#[derive(Default)]
struct FixtureAuth {
    trace: RefCell<Vec<(u8, Round, [u8; 32])>>,
}
impl FixtureAuth {
    fn record(&self, code: u8, round: Round, message: &[u8]) {
        self.trace
            .borrow_mut()
            .push((code, round, keccak256(message)));
    }
    fn recover(
        domain: &[u8],
        message: &[u8],
        signature: &SignatureBytes,
    ) -> Option<ValidatorAddress> {
        let address: [u8; 20] = signature.0[..20].try_into().ok()?;
        let mut bytes = domain.to_vec();
        bytes.extend_from_slice(message);
        bytes.extend_from_slice(&address);
        (signature.0[20..52] == keccak256(&bytes) && signature.0[52..].iter().all(|&b| b == 0))
            .then_some(ValidatorAddress(address))
    }
    fn output_trace(&self, out: &mut Vec<u8>) {
        let trace = self.trace.borrow();
        count(out, trace.len());
        for (code, round, hash) in trace.iter() {
            out.push(*code);
            word(out, round.0);
            out.extend_from_slice(hash);
        }
    }
}
impl AdmissionAuthenticator for FixtureAuth {
    fn expected_proposer(
        &self,
        round: Round,
        eligible: &[ValidatorAddress],
    ) -> Result<ValidatorAddress, AuthenticationError> {
        let mut message = Vec::new();
        word(&mut message, round.0);
        count(&mut message, eligible.len());
        for a in eligible {
            message.extend_from_slice(&a.0);
        }
        self.record(1, round, &message);
        eligible
            .first()
            .copied()
            .ok_or(AuthenticationError::proposer(None))
    }
    fn recover_qc_vote_signer(
        &self,
        qc: &Qc,
        signature: &SignatureBytes,
    ) -> Result<ValidatorAddress, AuthenticationError> {
        let mut message = Vec::new();
        qc_scalar(&mut message, qc);
        let mut traced = message.clone();
        traced.extend_from_slice(&signature.0);
        self.record(2, qc.round, &traced);
        Self::recover(b"fixture-qc-v1", &message, signature)
            .ok_or(AuthenticationError::QcVoteSignature)
    }
    fn recover_timeout_vote_signer(
        &self,
        qc: &Qc,
        round: Round,
        signature: &SignatureBytes,
    ) -> Result<ValidatorAddress, AuthenticationError> {
        let mut message = Vec::new();
        qc_scalar(&mut message, qc);
        word(&mut message, round.0);
        let mut traced = message.clone();
        traced.extend_from_slice(&signature.0);
        self.record(3, round, &traced);
        Self::recover(b"fixture-timeout-v1", &message, signature)
            .ok_or(AuthenticationError::TimeoutVoteSignature)
    }
    fn recover_block_signer(
        &self,
        _block: &SignedBlock,
    ) -> Result<ValidatorAddress, AuthenticationError> {
        // The new adapter must never call this incomplete legacy boundary.
        Err(AuthenticationError::BlockSignature)
    }
}
impl ClientBatchAuthenticator for FixtureAuth {
    fn recover_timed_block_signer(
        &self,
        block: &SignedBlock,
        time: ClientBlockTime,
    ) -> Result<ValidatorAddress, AuthenticationError> {
        let timed = TimedSignedBlock {
            block: block.clone(),
            time,
        };
        let mut traced = Vec::new();
        block_bytes(&mut traced, &timed);
        self.record(4, block.round, &traced);
        Self::recover(
            b"fixture-block-sign-v1",
            &unsigned_bytes(&timed),
            &block.signature,
        )
        .ok_or(AuthenticationError::BlockSignature)
    }
    fn client_block_digest(&self, block: &TimedSignedBlock) -> BlockHash {
        let message = unsigned_bytes(block);
        self.record(5, block.block.round, &message);
        let mut bytes = b"fixture-block-v1".to_vec();
        bytes.extend_from_slice(&message);
        BlockHash(keccak256(&bytes))
    }
}

fn status(out: &mut Vec<u8>, kind: u8, tag: u8, payload: &[u8]) {
    out.push(kind);
    out.push(tag);
    count(out, payload.len());
    out.extend_from_slice(payload);
}
fn admission(out: &mut Vec<u8>, error: &VerificationFailure) {
    match error {
        VerificationFailure::Fatal(error) => status(
            out,
            3,
            match error {
                FatalAdmissionError::StakeOverflow => 0,
                FatalAdmissionError::NewerHardforkWithQuorum => 1,
            },
            &[],
        ),
        VerificationFailure::Rejected(error) => {
            let mut payload = Vec::new();
            match error {
                AdmissionError::Hardfork { qc, node } => {
                    for value in [
                        qc.version,
                        qc.start_round.0,
                        node.version,
                        node.start_round.0,
                    ] {
                        word(&mut payload, value);
                    }
                }
                AdmissionError::BadBlockProposer { proposed, expected } => {
                    payload.extend_from_slice(&proposed.0);
                    payload.extend_from_slice(&expected.0);
                }
                AdmissionError::TimeoutRoundMismatch { supplied, expected } => {
                    word(&mut payload, supplied.0);
                    word(&mut payload, expected.0);
                }
                AdmissionError::MissingValidatorSetRound(round) => word(&mut payload, round.0),
                // These registration variants cannot arise from verify_block/QC/TC.
                AdmissionError::BlockRound { block, committed } => {
                    word(&mut payload, block.0);
                    word(&mut payload, committed.0);
                }
                AdmissionError::BlockAlreadyRegistered(hash) => payload.extend_from_slice(&hash.0),
                AdmissionError::DuplicateBlockRound { known, new } => {
                    payload.extend_from_slice(&known.0);
                    payload.extend_from_slice(&new.0);
                }
                _ => {}
            }
            status(out, 2, error.target_tag().unwrap_or(255), &payload);
        }
    }
}
fn batch_error(out: &mut Vec<u8>, error: &ClientBatchError) {
    if let ClientBatchError::Verification(error) = error {
        admission(out, error);
        return;
    }
    let mut payload = Vec::new();
    match error {
        ClientBatchError::QcRound { round, expected } => {
            word(&mut payload, round.0);
            word(&mut payload, expected.0);
        }
        ClientBatchError::QcHash { hash, expected } => {
            payload.extend_from_slice(&hash.0);
            payload.extend_from_slice(&expected.0);
        }
        ClientBatchError::TransactionHash(hash) => payload.extend_from_slice(&hash.0),
        _ => {}
    }
    status(
        out,
        1,
        error.target_tag().expect("local recovered tag"),
        &payload,
    );
}
fn buffer_status(out: &mut Vec<u8>, result: Result<(), ClientBufferError>) -> Result<(), String> {
    match result {
        Ok(()) => out.push(0),
        Err(ClientBufferError::UnexpectedRound(round)) => {
            status(out, 4, 44, &round.0.to_le_bytes())
        }
        Err(ClientBufferError::TooManyUnconfirmed) => {
            status(out, 4, 42, b"Too many unconfirmed blocks")
        }
        Err(ClientBufferError::ClosedChannel) => status(out, 4, 53, &[]),
        Err(ClientBufferError::Verification(error)) => batch_error(out, &error),
        Err(ClientBufferError::Input(_)) => return Err("outside supplied valid-span corpus".into()),
        Err(ClientBufferError::Allocation) => return Err("fixture allocation refused".into()),
    }
    Ok(())
}
struct Sink {
    accepted: Vec<ClientBlock>,
    events: Vec<Vec<u8>>,
    close_after: u64,
}
impl ClientBlockSink for Sink {
    fn send_or_return(&mut self, item: ClientBlock, view: ClientBufferView) -> Option<ClientBlock> {
        let accepted = (self.accepted.len() as u64) < self.close_after;
        let mut event = vec![u8::from(accepted)];
        word(&mut event, view.last_received.0);
        word(&mut event, view.confirmed.0);
        word(&mut event, view.pending_len as u64);
        event.extend_from_slice(&keccak256(&item_bytes(&item)));
        self.events.push(event);
        if accepted {
            self.accepted.push(item);
            None
        } else {
            Some(item)
        }
    }
}

fn evaluate(bytes: &[u8]) -> Result<Vec<u8>, String> {
    if bytes.len() > u32::MAX as usize {
        return Err("frame too large for u32 transport".into());
    }
    let mut reader = Reader { bytes, offset: 0 };
    if reader.take(3)? != b"CB1" {
        return Err("wrong framing version".into());
    }
    let mode = reader.byte()?;
    let history = reader.history()?;
    let auth = FixtureAuth::default();
    let mut out = Vec::new();
    match mode {
        0 => {
            let start = Round(reader.u64()?);
            let items = reader.items()?;
            if reader.offset != bytes.len() {
                return Err("trailing input bytes".into());
            }
            match verify_client_batch(&history, &auth, &items, start) {
                Ok(()) => out.push(0),
                Err(ClientBatchFailure::Rejected(error)) => batch_error(&mut out, &error),
                Err(ClientBatchFailure::Input(_)) => return Err("outside valid-span corpus".into()),
            }
        }
        1 => {
            let last = Round(reader.u64()?);
            let confirmed = Round(reader.u64()?);
            let pending = reader.items()?;
            let close_after = reader.u64()?;
            let items = reader.items()?;
            if reader.offset != bytes.len() {
                return Err("trailing input bytes".into());
            }
            if pending
                .len()
                .checked_add(items.len())
                .is_none_or(|n| n > u32::MAX as usize)
            {
                return Err("aggregate transport count".into());
            }
            let mut buffer = ClientBlockBuffer::from_parts(last, confirmed, pending)
                .map_err(|_| "outside valid-span corpus")?;
            let mut sink = Sink {
                accepted: Vec::new(),
                events: Vec::new(),
                close_after,
            };
            count(&mut out, items.len());
            for item in items {
                buffer_status(&mut out, buffer.push(&history, &auth, &mut sink, item))?;
                let view = buffer.view();
                word(&mut out, view.last_received.0);
                word(&mut out, view.confirmed.0);
                fingerprints(&mut out, buffer.pending());
                fingerprints(&mut out, &sink.accepted);
            }
            count(&mut out, sink.events.len());
            for event in sink.events {
                out.extend_from_slice(&event);
            }
        }
        _ => return Err("unknown mode".into()),
    }
    auth.output_trace(&mut out);
    Ok(out)
}
fn decode_hex(text: &str) -> Result<Vec<u8>, String> {
    if text.len() % 2 != 0 {
        return Err("odd hex length".into());
    }
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            fn nibble(b: u8) -> Option<u8> {
                match b {
                    b'0'..=b'9' => Some(b - b'0'),
                    b'a'..=b'f' => Some(b - b'a' + 10),
                    _ => None,
                }
            }
            Ok(nibble(pair[0]).ok_or("nonhex input")? * 16
                + nibble(pair[1]).ok_or("nonhex input")?)
        })
        .collect()
}
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(DIGITS[(byte >> 4) as usize] as char);
        result.push(DIGITS[(byte & 15) as usize] as char);
    }
    result
}
fn run() -> Result<(), String> {
    if std::env::args_os().len() != 1 {
        return Err("no arguments accepted".into());
    }
    let mut seen = BTreeSet::new();
    let mut output = io::BufWriter::new(io::stdout().lock());
    for line in io::stdin().lock().lines() {
        let line = line.map_err(|e| e.to_string())?;
        let (identifier, input) = line.split_once('\t').ok_or("line needs ID and input")?;
        if identifier.len() != 7
            || !identifier.starts_with('C')
            || !identifier.as_bytes()[1..].iter().all(u8::is_ascii_digit)
            || !seen.insert(identifier.to_owned())
        {
            return Err("invalid or duplicate opaque ID".into());
        }
        let result = evaluate(&decode_hex(input)?)?;
        writeln!(output, "{}\t{}", identifier, hex(&result)).map_err(|e| e.to_string())?;
    }
    output.flush().map_err(|e| e.to_string())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(2);
    }
}
