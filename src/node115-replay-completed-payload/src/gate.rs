//! Offline projection of the selected parent-round comparison.
use node115_client_block_success::{Parent, ReplayPayload, replay_parent_projection};

use crate::DecodedPrefix;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReceivedRounds {
    pub incoming: u64,
    pub parent: u64,
    pub baseline: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiveOrder {
    Older(ReceivedRounds),
    Equal(ReceivedRounds),
    Gap(ReceivedRounds),
}

fn parent_round(parent: &Parent) -> u64 {
    match parent {
        Parent::QuorumCertificate(certificate) => certificate.fields[2],
        Parent::Timeout {
            certificate,
            quorum_certificate,
        } => {
            quorum_certificate
                .as_ref()
                .unwrap_or(&certificate.quorum_certificate)
                .fields[2]
        }
    }
}

impl DecodedPrefix {
    /// Classify a Block that has already passed the two-word identity check.
    /// The tail is the completed result of the newest buffered Block, when
    /// present. A non-Block input or tail does not meet this adapter's domain.
    pub fn classify_receive_order(
        &self,
        startup_round: u64,
        tail: Option<&DecodedPrefix>,
    ) -> Option<ReceiveOrder> {
        let ReplayPayload::Block { block, .. } = self.result.as_ref().ok()? else {
            return None;
        };
        let baseline = if let Some(tail) = tail {
            let ReplayPayload::Block { block, .. } = tail.result.as_ref().ok()? else {
                return None;
            };
            replay_parent_projection(&block.header.parent).successor
        } else {
            startup_round
        };
        let rounds = ReceivedRounds {
            incoming: replay_parent_projection(&block.header.parent).successor,
            parent: parent_round(&block.header.parent),
            baseline,
        };
        Some(match rounds.parent.cmp(&rounds.baseline) {
            core::cmp::Ordering::Less => ReceiveOrder::Older(rounds),
            core::cmp::Ordering::Equal => ReceiveOrder::Equal(rounds),
            core::cmp::Ordering::Greater => ReceiveOrder::Gap(rounds),
        })
    }
}
