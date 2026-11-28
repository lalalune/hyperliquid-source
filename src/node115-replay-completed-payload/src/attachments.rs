//! Offline content and order checks for decoded replay Block fixtures.

use l1_shared::utils::keccak256;

use crate::{DecodedPrefix, ReplayPayload};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttachmentFixtureCheck {
    DecodeFailed,
    Tx,
    MissingOwner { expected: usize },
    ContentDigestMismatch { position: usize },
    CountMismatch { expected: usize, observed: usize },
    BlockDigestMismatch { position: usize },
    Ready { attachment_count: usize },
}

impl DecodedPrefix {
    /// Compare the prepared attachments available from the decoded fixture.
    ///
    /// A present owner is used as decoded. An absent owner with zero Block
    /// digests represents the empty handoff. Other absent owners require a
    /// separate source before the content checks can run.
    pub fn check_attachment_fixture(&self) -> AttachmentFixtureCheck {
        let Ok(payload) = &self.result else {
            return AttachmentFixtureCheck::DecodeFailed;
        };
        let ReplayPayload::Block { block, attachments } = payload else {
            return AttachmentFixtureCheck::Tx;
        };
        let expected = &block.header.hashes;
        let attachments = match attachments {
            Some(attachments) => attachments.as_slice(),
            None if expected.is_empty() => &[],
            None => {
                return AttachmentFixtureCheck::MissingOwner {
                    expected: expected.len(),
                };
            }
        };

        for (position, attachment) in attachments.iter().enumerate() {
            if keccak256(&attachment.bytes) != attachment.hash {
                return AttachmentFixtureCheck::ContentDigestMismatch { position };
            }
        }
        if attachments.len() != expected.len() {
            return AttachmentFixtureCheck::CountMismatch {
                expected: expected.len(),
                observed: attachments.len(),
            };
        }
        for (position, (attachment, digest)) in attachments.iter().zip(expected).enumerate() {
            if attachment.hash != *digest {
                return AttachmentFixtureCheck::BlockDigestMismatch { position };
            }
        }
        AttachmentFixtureCheck::Ready {
            attachment_count: attachments.len(),
        }
    }
}
