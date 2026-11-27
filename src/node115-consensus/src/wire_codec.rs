//! Node #115 five-variant consensus signing payload serializer (`0x5823db0..0x58241e1`)
//! and `try_propose` pre-proposal guards (`0x2e13ea0..0x2e153c9`; window `0x2e14036..0x2e140f9`).
//!
//! Backed by `research/work-items/RE-008-node115-consensus-crate-map`. Uses the
//! verified `node115-varint-buffer-writer` (`0x5822910`) for all bincode varint
//! fields.

use std::collections::BTreeSet;

use crate::block_rules::BlockProposerProvider;
use crate::round_progression::Address;
use crate::varint_writer::{Error as VarintError, write_u64};

/// Exact 1-byte variant tags emitted by `0x5823db0` (`0x5823f8d..0x582403c`).
pub const SIGNING_TAG_BLOCK: u8 = 0;
pub const SIGNING_TAG_VOTE: u8 = 1;
pub const SIGNING_TAG_TIMEOUT: u8 = 2;
pub const SIGNING_TAG_STATUS: u8 = 3;
pub const SIGNING_TAG_PEER_MSG: u8 = 4;

/// ZigZag encoding matching `0x4ecac42..0x4ecac51` and `0x5b56255..0x5b56264`:
/// `((v << 1) ^ (v >> 63)) as u64`.
pub const fn zigzag_encode_i64(v: i64) -> u64 {
    ((v << 1) ^ (v >> 63)) as u64
}

/// Appends a bincode varint `u32` matching `0x5821f30..0x58220d6`.
pub fn write_varint_u32(out: &mut Vec<u8>, value: u32) -> Result<(), VarintError> {
    write_u64(out, u64::from(value))
}

/// Variant `1` (`0x5966b90`): Vote signing payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VoteSigningPayload {
    pub voter: Address,
    pub hardfork_version: u64,
    pub hardfork_round: u64,
    pub round: u64,
    pub parent_round: u64,
    pub validator_set_round: u64,
    pub block_hash: [u8; 32],
}

impl VoteSigningPayload {
    /// Serializes exact `0x5823db0` variant-1 bytes (`0x01 || voter[20] || 5*varint(u64) || block_hash[32]`).
    pub fn encode_signing_bytes(&self) -> Result<Vec<u8>, VarintError> {
        let mut out = Vec::with_capacity(64);
        out.push(SIGNING_TAG_VOTE);
        out.extend_from_slice(&self.voter);
        write_u64(&mut out, self.hardfork_version)?;
        write_u64(&mut out, self.hardfork_round)?;
        write_u64(&mut out, self.round)?;
        write_u64(&mut out, self.parent_round)?;
        write_u64(&mut out, self.validator_set_round)?;
        out.extend_from_slice(&self.block_hash);
        Ok(out)
    }
}

/// Variant `2` (`0x5967d90`): Timeout signing payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimeoutSigningPayload {
    pub signer: Address,
    pub hardfork_version: u64,
    pub hardfork_round: u64,
    pub timeout_round: u64,
    pub high_qc_round: u64,
}

impl TimeoutSigningPayload {
    /// Serializes exact `0x5823db0` variant-2 bytes (`0x02 || signer[20] || 4*varint(u64)`).
    pub fn encode_signing_bytes(&self) -> Result<Vec<u8>, VarintError> {
        let mut out = Vec::with_capacity(40);
        out.push(SIGNING_TAG_TIMEOUT);
        out.extend_from_slice(&self.signer);
        write_u64(&mut out, self.hardfork_version)?;
        write_u64(&mut out, self.hardfork_round)?;
        write_u64(&mut out, self.timeout_round)?;
        write_u64(&mut out, self.high_qc_round)?;
        Ok(out)
    }
}

/// Variant `4` (`0x5b5b360`): Peer message signing payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerMsgSigningPayload {
    pub addr1: Address,
    pub addr2: Address,
    pub code: u32,
    pub value: u64,
}

impl PeerMsgSigningPayload {
    /// Serializes exact `0x5823db0` variant-4 bytes (`0x04 || addr1[20] || addr2[20] || varint(u32) || varint(u64)`).
    pub fn encode_signing_bytes(&self) -> Result<Vec<u8>, VarintError> {
        let mut out = Vec::with_capacity(56);
        out.push(SIGNING_TAG_PEER_MSG);
        out.extend_from_slice(&self.addr1);
        out.extend_from_slice(&self.addr2);
        write_varint_u32(&mut out, self.code)?;
        write_u64(&mut out, self.value)?;
        Ok(out)
    }
}

/// Variant `0` (`0x5967060`) prefix encoder: tag `0`, proposer, tx hashes,
/// timestamp `(zigzag_varint(unix_secs), varint_u32(nanos))` (`0x4ecaba0`),
/// plus caller-provided justification bytes (`0 => QC`, `1 => TC`).
pub fn encode_block_signing_payload(
    proposer: &Address,
    tx_hashes: &[[u8; 32]],
    unix_secs: i64,
    nanos: u32,
    justification_bytes: &[u8],
) -> Result<Vec<u8>, VarintError> {
    let mut out = Vec::with_capacity(32 + tx_hashes.len() * 32 + justification_bytes.len());
    out.push(SIGNING_TAG_BLOCK);
    out.extend_from_slice(proposer);
    write_u64(&mut out, tx_hashes.len() as u64)?;
    for h in tx_hashes {
        out.extend_from_slice(h);
    }
    write_u64(&mut out, zigzag_encode_i64(unix_secs))?;
    write_varint_u32(&mut out, nanos)?;
    out.extend_from_slice(justification_bytes);
    Ok(out)
}

/// Outcome of `try_propose`'s pre-proposal guards (`0x2e14036..0x2e14137`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TryProposeDecision<PE> {
    /// Allowed to construct and broadcast a block for `current_round`.
    Propose,
    /// Proposer lookup (`0x64e86f0`) failed.
    ProposerLookupFailed(PE),
    /// Scheduled proposer for `current_round` is not `self_address`.
    NotLeader { leader: Address },
    /// Anti-equivocation guard (`0x2e140bc..0x2e140ca`): `last_proposed_round >= current_round`.
    AlreadyProposedForRound { last_proposed_round: u64 },
    /// `self_address` is not present in the active stake set for `stake_round`.
    SelfNotInStakeSet,
}

/// Reconstructs the exact guard order in `0x2e13ea0` (`0x2e14036..0x2e14137`):
/// 1. Lookup proposer `(current_round, stake_round)` via `0x64e86f0`.
/// 2. 20-byte equality against `self_address`.
/// 3. Anti-equivocation check `last_proposed_round < current_round`.
/// 4. Active stake-set membership check for `self_address`.
pub fn evaluate_try_propose_guards<P: BlockProposerProvider>(
    proposer_provider: &P,
    self_address: Address,
    current_round: u64,
    stake_round: u64,
    last_proposed_round: Option<u64>,
    active_validators: &BTreeSet<Address>,
) -> TryProposeDecision<P::Error> {
    let leader = match proposer_provider.proposer_for_block(current_round, stake_round) {
        Ok(addr) => addr,
        Err(err) => return TryProposeDecision::ProposerLookupFailed(err),
    };
    if leader != self_address {
        return TryProposeDecision::NotLeader { leader };
    }
    if let Some(last) = last_proposed_round
        && last >= current_round
    {
        return TryProposeDecision::AlreadyProposedForRound {
            last_proposed_round: last,
        };
    }
    if !active_validators.contains(&self_address) {
        return TryProposeDecision::SelfNotInStakeSet;
    }
    TryProposeDecision::Propose
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proposer::ProposerScheduleHistory;

    fn addr(b: u8) -> Address {
        [b; 20]
    }

    #[test]
    fn vote_timeout_and_peer_serializers_match_0x5823db0_layout() {
        let vote = VoteSigningPayload {
            voter: addr(0xaa),
            hardfork_version: 1,
            hardfork_round: 2,
            round: 300, // 0xfb + 0x2c 0x01
            parent_round: 299,
            validator_set_round: 250,
            block_hash: [0xbb; 32],
        };
        let bytes = vote.encode_signing_bytes().unwrap();
        assert_eq!(bytes[0], 1);
        assert_eq!(&bytes[1..21], &[0xaa; 20]);
        assert_eq!(&bytes[21..23], &[1, 2]);
        assert_eq!(&bytes[23..26], &[0xfb, 0x2c, 0x01]);
        assert_eq!(&bytes[bytes.len() - 32..], &[0xbb; 32]);

        let to = TimeoutSigningPayload {
            signer: addr(0xcc),
            hardfork_version: 7,
            hardfork_round: 8,
            timeout_round: 9,
            high_qc_round: 8,
        };
        let tbytes = to.encode_signing_bytes().unwrap();
        assert_eq!(tbytes.len(), 1 + 20 + 4);
        assert_eq!(tbytes[0], 2);
        assert_eq!(&tbytes[1..21], &[0xcc; 20]);
        assert_eq!(&tbytes[21..25], &[7, 8, 9, 8]);

        let pm = PeerMsgSigningPayload {
            addr1: addr(1),
            addr2: addr(2),
            code: 70_000,
            value: 42,
        };
        let pbytes = pm.encode_signing_bytes().unwrap();
        assert_eq!(pbytes[0], 4);
        assert_eq!(pbytes[41], 0xfc); // u32 >= 65536
        assert_eq!(pbytes[46], 42);
    }

    #[test]
    fn zigzag_and_try_propose_guards_work_end_to_end() {
        assert_eq!(zigzag_encode_i64(0), 0);
        assert_eq!(zigzag_encode_i64(-1), 1);
        assert_eq!(zigzag_encode_i64(1), 2);
        assert_eq!(zigzag_encode_i64(-2), 3);

        let hist = ProposerScheduleHistory {
            jailed_base_round: 0,
            jailed_snapshots: vec![(0, vec![])],
            stake_base_round: 0,
            stake_snapshots: vec![(0, vec![(addr(1), 1)])],
            extra_members: vec![],
        };
        let mut active = BTreeSet::new();
        active.insert(addr(1));

        assert_eq!(
            evaluate_try_propose_guards(&hist, addr(2), 10, 0, None, &active),
            TryProposeDecision::NotLeader { leader: addr(1) }
        );
        assert_eq!(
            evaluate_try_propose_guards(&hist, addr(1), 10, 0, Some(10), &active),
            TryProposeDecision::AlreadyProposedForRound {
                last_proposed_round: 10,
            }
        );
        assert_eq!(
            evaluate_try_propose_guards(&hist, addr(1), 10, 0, Some(9), &BTreeSet::new()),
            TryProposeDecision::SelfNotInStakeSet
        );
        assert_eq!(
            evaluate_try_propose_guards(&hist, addr(1), 10, 0, Some(9), &active),
            TryProposeDecision::Propose
        );
    }
}
