use node94_consensus_admission::*;
use std::cell::RefCell;
use std::collections::BTreeMap;

const ADDRESS: ValidatorAddress = ValidatorAddress([1; 20]);
const TIME: ClientBlockTime = ClientBlockTime([7, 8, 9]);

#[derive(Default)]
struct Auth {
    calls: RefCell<Vec<String>>,
}

// This small independent test boundary is not a target cryptographic oracle.
impl AdmissionAuthenticator for Auth {
    fn expected_proposer(
        &self,
        round: Round,
        eligible: &[ValidatorAddress],
    ) -> Result<ValidatorAddress, AuthenticationError> {
        self.calls
            .borrow_mut()
            .push(format!("proposer:{}", round.0));
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
        self.calls.borrow_mut().push(format!("qc:{}", qc.round.0));
        if signature.0[0] == 1 {
            Ok(ADDRESS)
        } else {
            Err(AuthenticationError::QcVoteSignature)
        }
    }

    fn recover_timeout_vote_signer(
        &self,
        _qc: &Qc,
        _round: Round,
        _signature: &SignatureBytes,
    ) -> Result<ValidatorAddress, AuthenticationError> {
        panic!("no timeout in these handwritten tests")
    }

    fn recover_block_signer(
        &self,
        _block: &SignedBlock,
    ) -> Result<ValidatorAddress, AuthenticationError> {
        panic!("the new adapter must use complete timed authentication")
    }
}

impl ClientBatchAuthenticator for Auth {
    fn recover_timed_block_signer(
        &self,
        block: &SignedBlock,
        time: ClientBlockTime,
    ) -> Result<ValidatorAddress, AuthenticationError> {
        self.calls
            .borrow_mut()
            .push(format!("block:{}", block.round.0));
        if block.signature.0[0] == 1 && block.signature.0[1] == time.0[0] as u8 {
            Ok(ADDRESS)
        } else {
            Err(AuthenticationError::BlockSignature)
        }
    }

    fn client_block_digest(&self, block: &TimedSignedBlock) -> BlockHash {
        self.calls
            .borrow_mut()
            .push(format!("digest:{}", block.block.round.0));
        fixture_digest(block.block.round.0)
    }
}

fn fixture_digest(round: u64) -> BlockHash {
    BlockHash([round as u8; 32])
}

fn signature() -> SignatureBytes {
    let mut bytes = [0; 72];
    bytes[0] = 1;
    bytes[1] = 7;
    SignatureBytes(bytes)
}

fn history() -> StakeHistory {
    StakeHistory {
        base_round: Round(0),
        hardfork: Hardfork {
            version: 1,
            start_round: Round(0),
        },
        estimated_valid_until: Round(u64::MAX),
        snapshots: BTreeMap::from([(
            Round(0),
            StakeSnapshot {
                stakes: BTreeMap::from([(ADDRESS, 10)]),
            },
        )]),
    }
}

fn qc(round: u64, hash: BlockHash) -> Qc {
    Qc {
        hardfork: Hardfork {
            version: 1,
            start_round: Round(0),
        },
        round: Round(round),
        block_hash: hash,
        votes: if round == 0 {
            Vec::new()
        } else {
            vec![QcVote {
                signer: ADDRESS,
                signature: signature(),
            }]
        },
    }
}

fn block(round: u64, parent: u64, hash: BlockHash) -> TimedSignedBlock {
    TimedSignedBlock {
        block: SignedBlock {
            transaction_hashes: Vec::new(),
            qc: qc(parent, hash),
            tc: None,
            round: Round(round),
            proposer: ADDRESS,
            signature: signature(),
        },
        time: TIME,
    }
}

fn item(round: u64, parent: u64, proof: bool) -> ClientBlock {
    ClientBlock {
        signed: block(round, parent, fixture_digest(parent)),
        transactions: Vec::new(),
        copied_time: TIME,
        proof: proof.then(|| ClientCommitProof {
            child: block(round.saturating_add(1), round, fixture_digest(round)),
            qc: qc(
                round.saturating_add(1),
                fixture_digest(round.saturating_add(1)),
            ),
        }),
    }
}

#[derive(Default)]
struct Sink {
    accepted: Vec<ClientBlock>,
    views: Vec<ClientBufferView>,
    limit: Option<usize>,
}

impl ClientBlockSink for Sink {
    fn send_or_return(&mut self, item: ClientBlock, view: ClientBufferView) -> Option<ClientBlock> {
        self.views.push(view);
        if self.limit.is_some_and(|limit| self.accepted.len() >= limit) {
            Some(item)
        } else {
            self.accepted.push(item);
            None
        }
    }
}

#[test]
fn empty_stake_two_call_counterexample_needs_no_authenticator() {
    let mut history = history();
    history.snapshots.clear();
    let auth = Auth::default();
    let mut buffer = ClientBlockBuffer::default();
    let mut sink = Sink::default();
    assert_eq!(
        buffer.push(&history, &auth, &mut sink, item(1, 0, true)),
        Err(ClientBufferError::Verification(
            ClientBatchError::Verification(VerificationFailure::Rejected(
                AdmissionError::MissingValidatorSetRound(Round(1))
            ))
        ))
    );
    assert_eq!(
        buffer.view(),
        ClientBufferView {
            last_received: Round(1),
            confirmed: Round(0),
            pending_len: 1
        }
    );
    assert_eq!(
        buffer.push(&history, &auth, &mut sink, item(2, 1, true)),
        Err(ClientBufferError::Verification(
            ClientBatchError::UnexpectedCommitProof
        ))
    );
    assert_eq!(
        buffer.view(),
        ClientBufferView {
            last_received: Round(2),
            confirmed: Round(0),
            pending_len: 2
        }
    );
    assert!(auth.calls.borrow().is_empty() && sink.accepted.is_empty());
}

#[test]
fn no_proof_limit_retains_the_101st_record_and_round() {
    let mut buffer = ClientBlockBuffer::default();
    let auth = Auth::default();
    let mut sink = Sink::default();
    for round in 1..=100 {
        assert_eq!(
            buffer.push(&history(), &auth, &mut sink, item(round, round - 1, false)),
            Ok(())
        );
    }
    assert_eq!(
        buffer.push(&history(), &auth, &mut sink, item(101, 100, false)),
        Err(ClientBufferError::TooManyUnconfirmed)
    );
    assert_eq!(
        buffer.view(),
        ClientBufferView {
            last_received: Round(101),
            confirmed: Round(0),
            pending_len: 101
        }
    );
    assert!(auth.calls.borrow().is_empty());
}

#[test]
fn proof_flush_above_limit_confirms_and_clears_before_first_send() {
    let mut buffer = ClientBlockBuffer::default();
    let auth = Auth::default();
    let mut sink = Sink::default();
    for round in 1..=101 {
        buffer
            .push(
                &history(),
                &auth,
                &mut sink,
                item(round, round - 1, round == 101),
            )
            .unwrap();
    }
    assert_eq!(sink.accepted.len(), 101);
    assert!(sink.views.iter().all(|view| *view
        == ClientBufferView {
            last_received: Round(101),
            confirmed: Round(101),
            pending_len: 0
        }));
}

#[test]
fn closed_sink_keeps_the_accepted_prefix_and_advanced_state() {
    let mut buffer = ClientBlockBuffer::default();
    let auth = Auth::default();
    let mut sink = Sink {
        limit: Some(1),
        ..Sink::default()
    };
    buffer
        .push(&history(), &auth, &mut sink, item(1, 0, false))
        .unwrap();
    buffer
        .push(&history(), &auth, &mut sink, item(2, 1, false))
        .unwrap();
    assert_eq!(
        buffer.push(&history(), &auth, &mut sink, item(3, 2, true)),
        Err(ClientBufferError::ClosedChannel)
    );
    assert_eq!(sink.accepted[0].signed.block.round, Round(1));
    assert_eq!(sink.accepted.len(), 1);
    assert_eq!(sink.views.len(), 2);
    assert_eq!(
        buffer.view(),
        ClientBufferView {
            last_received: Round(3),
            confirmed: Round(3),
            pending_len: 0
        }
    );
    assert!(sink.views.iter().all(|view| *view == buffer.view()));
}

#[test]
fn outer_round_rejection_leaves_existing_pending_unchanged() {
    let pending = vec![item(1, 0, false)];
    let mut buffer = ClientBlockBuffer::from_parts(Round(1), Round(0), pending.clone()).unwrap();
    let auth = Auth::default();
    assert_eq!(
        buffer.push(&history(), &auth, &mut Sink::default(), item(4, 3, true)),
        Err(ClientBufferError::UnexpectedRound(Round(3)))
    );
    assert_eq!(buffer.pending(), pending);
    assert_eq!(buffer.view().last_received, Round(1));
    assert!(auth.calls.borrow().is_empty());
}

#[test]
fn proof_placement_precedes_round_and_empty_is_a_distinct_error() {
    let auth = Auth::default();
    assert_eq!(
        verify_client_batch(&history(), &auth, &[], Round(0)),
        Err(ClientBatchFailure::Rejected(ClientBatchError::NoBlocks))
    );
    let rows = [item(7, 6, true), item(8, 7, true)];
    assert_eq!(
        verify_client_batch(&history(), &auth, &rows, Round(0)),
        Err(ClientBatchFailure::Rejected(
            ClientBatchError::UnexpectedCommitProof
        ))
    );
    assert!(auth.calls.borrow().is_empty());
}

#[test]
fn transactions_are_hashed_before_count_and_time() {
    let mut row = item(1, 0, true);
    row.transactions.push(ClientTransaction {
        hash: TransactionHash([0; 32]),
        bytes: b"alpha".to_vec(),
    });
    row.copied_time = ClientBlockTime([0; 3]);
    assert_eq!(
        verify_client_batch(&history(), &Auth::default(), &[row], Round(0)),
        Err(ClientBatchFailure::Rejected(
            ClientBatchError::TransactionHash(TransactionHash([0; 32]))
        ))
    );
}

#[test]
fn timed_authentication_cannot_silently_use_the_old_untimed_method() {
    let mut row = item(1, 0, true);
    row.signed.time.0[0] = 8;
    row.copied_time = row.signed.time;
    assert_eq!(
        verify_client_batch(&history(), &Auth::default(), &[row], Round(0)),
        Err(ClientBatchFailure::Rejected(
            ClientBatchError::Verification(VerificationFailure::Rejected(
                AdmissionError::Signature
            ))
        ))
    );
}

#[test]
fn repeated_digests_and_proof_qc_verification_order_are_observable() {
    let auth = Auth::default();
    let mut row = item(1, 0, true);
    row.proof.as_mut().unwrap().qc.block_hash = BlockHash([77; 32]);
    assert_eq!(
        verify_client_batch(&history(), &auth, &[row], Round(0)),
        Err(ClientBatchFailure::Rejected(ClientBatchError::ProofQcHash))
    );
    let calls = auth.calls.borrow();
    let digests: Vec<_> = calls
        .iter()
        .filter(|call| call.starts_with("digest:"))
        .cloned()
        .collect();
    assert_eq!(digests, ["digest:1", "digest:1", "digest:2", "digest:2"]);
    assert!(
        calls.iter().position(|call| call == "qc:2").unwrap()
            < calls.iter().position(|call| call == "digest:2").unwrap()
    );
}

#[test]
fn first_parent_hash_and_internal_round_gaps_are_not_extra_gates() {
    let first = item(8, 5, false);
    let last = item(20, 8, true);
    assert_eq!(
        verify_client_batch(&history(), &Auth::default(), &[first, last], Round(5)),
        Ok(())
    );
}
