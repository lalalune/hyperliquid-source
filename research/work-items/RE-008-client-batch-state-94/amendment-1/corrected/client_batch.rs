//! Joined client-block batches and their retained buffer state.
//!
//! Native correspondence is conditional on RE-008-client-batch-state-94's
//! valid-memory, ordinary-return, frame and authenticator premises. The inherited
//! TC verifier's competing parallel failures remain outside that correspondence.

#![forbid(unsafe_code)]

use crate::{
    verify_block, verify_qc, AdmissionAuthenticator, AuthenticationError, BlockHash, Qc, Round,
    SignatureBytes, SignedBlock, StakeHistory, Tc, TransactionHash, ValidatorAddress,
    VerificationFailure,
};
use node94_action_signable::keccak256;

/// Three raw u32 words; no date validity or interpretation is imposed here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientBlockTime(pub [u32; 3]);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimedSignedBlock {
    pub block: SignedBlock,
    pub time: ClientBlockTime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientTransaction {
    pub hash: TransactionHash,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientCommitProof {
    pub child: TimedSignedBlock,
    pub qc: Qc,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientBlock {
    pub signed: TimedSignedBlock,
    pub transactions: Vec<ClientTransaction>,
    pub copied_time: ClientBlockTime,
    pub proof: Option<ClientCommitProof>,
}

/// Complete timed authentication is required; neither method drops time by default.
///
/// Implementations must preserve all input/state values and return normally for
/// the native correspondence. The digest must be stable on equal complete signed
/// values. It may record calls: the batch intentionally repeats some digests.
/// No native preimage or signature implementation is supplied by this module.
pub trait ClientBatchAuthenticator: AdmissionAuthenticator {
    fn recover_timed_block_signer(
        &self,
        block: &SignedBlock,
        time: ClientBlockTime,
    ) -> Result<ValidatorAddress, AuthenticationError>;

    fn client_block_digest(&self, block: &TimedSignedBlock) -> BlockHash;
}

struct TimedAdapter<'a, A> {
    authenticator: &'a A,
    time: ClientBlockTime,
}

impl<A: ClientBatchAuthenticator> AdmissionAuthenticator for TimedAdapter<'_, A> {
    fn expected_proposer(
        &self,
        round: Round,
        eligible: &[ValidatorAddress],
    ) -> Result<ValidatorAddress, AuthenticationError> {
        self.authenticator.expected_proposer(round, eligible)
    }

    fn recover_qc_vote_signer(
        &self,
        qc: &Qc,
        signature: &SignatureBytes,
    ) -> Result<ValidatorAddress, AuthenticationError> {
        self.authenticator.recover_qc_vote_signer(qc, signature)
    }

    fn recover_timeout_vote_signer(
        &self,
        qc: &Qc,
        round: Round,
        signature: &SignatureBytes,
    ) -> Result<ValidatorAddress, AuthenticationError> {
        self.authenticator
            .recover_timeout_vote_signer(qc, round, signature)
    }

    fn recover_block_signer(
        &self,
        block: &SignedBlock,
    ) -> Result<ValidatorAddress, AuthenticationError> {
        self.authenticator
            .recover_timed_block_signer(block, self.time)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientSpanField {
    Items,
    TransactionRows,
    TransactionBytes,
    BlockHashes,
    QcVotes,
    TimeoutVotes,
}

/// Safe input admission, separate from all recovered native semantic errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientSpanError {
    pub field: ClientSpanField,
    pub length: usize,
}

fn span(length: usize, width: usize, field: ClientSpanField) -> Result<(), ClientSpanError> {
    if length
        .checked_mul(width)
        .is_none_or(|bytes| bytes > isize::MAX as usize)
    {
        return Err(ClientSpanError { field, length });
    }
    Ok(())
}

fn qc_span(qc: &Qc) -> Result<(), ClientSpanError> {
    span(qc.votes.len(), 96, ClientSpanField::QcVotes)
}

fn tc_span(tc: &Tc) -> Result<(), ClientSpanError> {
    span(tc.votes.len(), 184, ClientSpanField::TimeoutVotes)?;
    for vote in &tc.votes {
        qc_span(&vote.qc)?;
    }
    Ok(())
}

fn block_span(block: &TimedSignedBlock) -> Result<(), ClientSpanError> {
    span(
        block.block.transaction_hashes.len(),
        32,
        ClientSpanField::BlockHashes,
    )?;
    qc_span(&block.block.qc)?;
    if let Some(tc) = &block.block.tc {
        tc_span(tc)?;
    }
    Ok(())
}

fn item_span(item: &ClientBlock) -> Result<(), ClientSpanError> {
    block_span(&item.signed)?;
    span(
        item.transactions.len(),
        40,
        ClientSpanField::TransactionRows,
    )?;
    for transaction in &item.transactions {
        span(
            transaction.bytes.len(),
            1,
            ClientSpanField::TransactionBytes,
        )?;
    }
    if let Some(proof) = &item.proof {
        block_span(&proof.child)?;
        qc_span(&proof.qc)?;
    }
    Ok(())
}

fn batch_span(items: &[ClientBlock]) -> Result<(), ClientSpanError> {
    span(items.len(), 32, ClientSpanField::Items)?;
    for item in items {
        item_span(item)?;
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClientBatchError {
    NoBlocks,
    QcRound {
        round: Round,
        expected: Round,
    },
    QcHash {
        hash: BlockHash,
        expected: BlockHash,
    },
    TransactionHash(TransactionHash),
    TransactionHashes,
    Time,
    UnexpectedCommitProof,
    MissingCommitProof,
    ChildQcHash,
    ProofQcHash,
    NonconsecutiveChild,
    Verification(VerificationFailure),
}

impl ClientBatchError {
    /// A fatal dependency result has no native ordinary-return tag.
    pub fn target_tag(&self) -> Option<u8> {
        Some(match self {
            Self::NoBlocks => 0x14,
            Self::QcRound { .. } => 0x15,
            Self::QcHash { .. } => 0x16,
            Self::TransactionHash(_) => 0x17,
            Self::TransactionHashes => 0x18,
            Self::Time => 0x19,
            Self::UnexpectedCommitProof => 0x1a,
            Self::MissingCommitProof => 0x1b,
            Self::ChildQcHash => 0x1d,
            Self::ProofQcHash => 0x1e,
            Self::NonconsecutiveChild => 0x1f,
            Self::Verification(VerificationFailure::Rejected(error)) => return error.target_tag(),
            Self::Verification(VerificationFailure::Fatal(_)) => return None,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClientBatchFailure {
    Input(ClientSpanError),
    Rejected(ClientBatchError),
}

fn verify_timed<A: ClientBatchAuthenticator>(
    history: &StakeHistory,
    authenticator: &A,
    block: &TimedSignedBlock,
) -> Result<(), ClientBatchError> {
    let adapter = TimedAdapter {
        authenticator,
        time: block.time,
    };
    verify_block(history, &adapter, &block.block)
        .map(|_| ())
        .map_err(ClientBatchError::Verification)
}

/// Verify all joined rows and the last commit proof in the recovered order.
///
/// All native spans are admitted before semantic work. Real baseline admission
/// performs certificate/membership/quorum checks. Competing failing TC children
/// retain the baseline safe policy and have no newly proved native precedence.
pub fn verify_client_batch<A: ClientBatchAuthenticator>(
    history: &StakeHistory,
    authenticator: &A,
    items: &[ClientBlock],
    start_round: Round,
) -> Result<(), ClientBatchFailure> {
    batch_span(items).map_err(ClientBatchFailure::Input)?;
    verify_admitted_batch(history, authenticator, items, start_round)
        .map_err(ClientBatchFailure::Rejected)
}

fn verify_admitted_batch<A: ClientBatchAuthenticator>(
    history: &StakeHistory,
    authenticator: &A,
    items: &[ClientBlock],
    start_round: Round,
) -> Result<(), ClientBatchError> {
    let last = items.last().ok_or(ClientBatchError::NoBlocks)?;
    let mut expected_round = start_round;
    let mut previous_hash = None;
    for (index, item) in items.iter().enumerate() {
        let block = &item.signed.block;
        if item.proof.is_some() && index + 1 != items.len() {
            return Err(ClientBatchError::UnexpectedCommitProof);
        }
        if block.qc.round != expected_round {
            return Err(ClientBatchError::QcRound {
                round: block.qc.round,
                expected: expected_round,
            });
        }
        if let Some(expected) = previous_hash {
            if block.qc.block_hash != expected {
                return Err(ClientBatchError::QcHash {
                    hash: block.qc.block_hash,
                    expected,
                });
            }
        }
        verify_timed(history, authenticator, &item.signed)?;
        // Hash every tx before comparing the count or block hash vector.
        for transaction in &item.transactions {
            if *keccak256(&transaction.bytes).as_bytes() != transaction.hash.0 {
                return Err(ClientBatchError::TransactionHash(transaction.hash));
            }
        }
        if item.transactions.len() != block.transaction_hashes.len()
            || item
                .transactions
                .iter()
                .zip(&block.transaction_hashes)
                .any(|(transaction, hash)| transaction.hash != *hash)
        {
            return Err(ClientBatchError::TransactionHashes);
        }
        if item.copied_time != item.signed.time {
            return Err(ClientBatchError::Time);
        }
        expected_round = block.round;
        previous_hash = Some(authenticator.client_block_digest(&item.signed));
    }
    let proof = last
        .proof
        .as_ref()
        .ok_or(ClientBatchError::MissingCommitProof)?;
    let last_hash = authenticator.client_block_digest(&last.signed);
    verify_timed(history, authenticator, &proof.child)?;
    verify_qc(history, authenticator, &proof.qc).map_err(ClientBatchError::Verification)?;
    if proof.child.block.qc.block_hash != last_hash {
        return Err(ClientBatchError::ChildQcHash);
    }
    let child_hash = authenticator.client_block_digest(&proof.child);
    if proof.qc.block_hash != child_hash {
        // The native mismatch path hashes the child again after its opaque getter.
        // Its result is unused; the digest boundary call remains observable.
        let _ = authenticator.client_block_digest(&proof.child);
        return Err(ClientBatchError::ProofQcHash);
    }
    if proof.child.block.round.0 != last.signed.block.round.0.saturating_add(1) {
        return Err(ClientBatchError::NonconsecutiveChild);
    }
    Ok(())
}

/// Immutable safe-adapter observation, not a native channel ABI.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientBufferView {
    pub last_received: Round,
    pub confirmed: Round,
    pub pending_len: usize,
}

/// Own each accepted item, or return that same item when the sink is closed.
/// This is an ordered handoff contract, not downstream delivery or linearizability.
pub trait ClientBlockSink {
    /// None accepts ownership; Some returns the same item because the sink is closed.
    fn send_or_return(&mut self, item: ClientBlock, view: ClientBufferView) -> Option<ClientBlock>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClientBufferError {
    Input(ClientSpanError),
    Allocation,
    UnexpectedRound(Round),
    TooManyUnconfirmed,
    Verification(ClientBatchError),
    ClosedChannel,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientBlockBuffer {
    last_received: Round,
    confirmed: Round,
    pending: Vec<ClientBlock>,
}

impl Default for ClientBlockBuffer {
    fn default() -> Self {
        Self {
            last_received: Round(0),
            confirmed: Round(0),
            pending: Vec::new(),
        }
    }
}

impl ClientBlockBuffer {
    /// Admit explicit supplied state; this does not invent a valid history rule.
    pub fn from_parts(
        last_received: Round,
        confirmed: Round,
        pending: Vec<ClientBlock>,
    ) -> Result<Self, ClientSpanError> {
        batch_span(&pending)?;
        Ok(Self {
            last_received,
            confirmed,
            pending,
        })
    }

    pub fn view(&self) -> ClientBufferView {
        ClientBufferView {
            last_received: self.last_received,
            confirmed: self.confirmed,
            pending_len: self.pending.len(),
        }
    }

    pub fn pending(&self) -> &[ClientBlock] {
        &self.pending
    }

    /// Append before verification; recoverable verification errors retain state.
    ///
    /// Span/reserve refusals are safe policies outside the native ordinary domain.
    /// Dependency allocations and callback panics are not recovered. Success
    /// confirms and takes the whole pending vector before any sink observation.
    pub fn push<A: ClientBatchAuthenticator, S: ClientBlockSink>(
        &mut self,
        history: &StakeHistory,
        authenticator: &A,
        sink: &mut S,
        item: ClientBlock,
    ) -> Result<(), ClientBufferError> {
        batch_span(&self.pending).map_err(ClientBufferError::Input)?;
        item_span(&item).map_err(ClientBufferError::Input)?;
        let length = self
            .pending
            .len()
            .checked_add(1)
            .ok_or(ClientBufferError::Input(ClientSpanError {
                field: ClientSpanField::Items,
                length: usize::MAX,
            }))?;
        span(length, 32, ClientSpanField::Items).map_err(ClientBufferError::Input)?;
        if item.signed.block.qc.round != self.last_received {
            return Err(ClientBufferError::UnexpectedRound(
                item.signed.block.qc.round,
            ));
        }
        self.pending
            .try_reserve(1)
            .map_err(|_| ClientBufferError::Allocation)?;
        self.last_received = item.signed.block.round;
        let has_proof = item.proof.is_some();
        self.pending.push(item);
        if !has_proof {
            return if self.pending.len() <= 100 {
                Ok(())
            } else {
                Err(ClientBufferError::TooManyUnconfirmed)
            };
        }
        verify_admitted_batch(history, authenticator, &self.pending, self.confirmed)
            .map_err(ClientBufferError::Verification)?;
        self.confirmed = self.last_received;
        let drained = std::mem::take(&mut self.pending);
        let view = self.view();
        for item in drained {
            if let Some(item) = sink.send_or_return(item, view) {
                drop(item);
                return Err(ClientBufferError::ClosedChannel);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod length_tests {
    use super::*;

    #[test]
    fn native_span_refusals_without_allocating_large_objects() {
        // Safe-source admission probes, not additional native fixture executions.
        for (width, field) in [
            (32, ClientSpanField::Items),
            (40, ClientSpanField::TransactionRows),
            (1, ClientSpanField::TransactionBytes),
            (32, ClientSpanField::BlockHashes),
            (96, ClientSpanField::QcVotes),
            (184, ClientSpanField::TimeoutVotes),
        ] {
            let maximum = isize::MAX as usize / width;
            assert_eq!(span(maximum, width, field), Ok(()));
            assert_eq!(
                span(maximum + 1, width, field),
                Err(ClientSpanError {
                    field,
                    length: maximum + 1,
                })
            );
            assert!(span(usize::MAX, width, field).is_err());
        }
    }
}
