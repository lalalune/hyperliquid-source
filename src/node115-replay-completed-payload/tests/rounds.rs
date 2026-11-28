use node115_client_block_success::{
    Block, Header, Parent, QuorumCertificate, Signature, TimeoutCertificate, admit_timestamp,
};
use node115_replay_completed_payload::{
    DecodedPrefix, ReceiveOrder, ReceivedRounds, ReplayPayload,
};

fn quorum(round: u64) -> QuorumCertificate {
    QuorumCertificate {
        fields: [1, 2, round, 4, 5],
        hash: [0; 32],
        votes: vec![],
    }
}

fn decoded(parent: Parent) -> DecodedPrefix {
    DecodedPrefix {
        result: Ok(ReplayPayload::Block {
            block: Box::new(Block {
                signature: Signature {
                    limbs: [0; 8],
                    recovery: 0,
                },
                header: Header {
                    address: [0; 20],
                    hashes: vec![],
                    timestamp: admit_timestamp(0, 0).unwrap(),
                    parent,
                },
                commit_proof: None,
            }),
            attachments: None,
        }),
        decoder_input_len: 0,
        consumed: 0,
        charged: 0,
    }
}

#[test]
fn three_parent_layouts_produce_distinct_basis_and_parent_rounds() {
    assert_eq!(
        decoded(Parent::QuorumCertificate(quorum(15))).classify_receive_order(15, None),
        Some(ReceiveOrder::Equal(ReceivedRounds {
            incoming: 16,
            parent: 15,
            baseline: 15
        }))
    );
    let timeout = TimeoutCertificate {
        field: 31,
        quorum_certificate: quorum(12),
        votes: vec![],
    };
    assert_eq!(
        decoded(Parent::Timeout {
            certificate: timeout.clone(),
            quorum_certificate: None
        })
        .classify_receive_order(15, None),
        Some(ReceiveOrder::Older(ReceivedRounds {
            incoming: 32,
            parent: 12,
            baseline: 15
        }))
    );
    assert_eq!(
        decoded(Parent::Timeout {
            certificate: timeout,
            quorum_certificate: Some(quorum(19))
        })
        .classify_receive_order(15, None),
        Some(ReceiveOrder::Gap(ReceivedRounds {
            incoming: 32,
            parent: 19,
            baseline: 15
        }))
    );
}

#[test]
fn receive_tail_uses_its_own_saturating_successor() {
    let first = decoded(Parent::QuorumCertificate(quorum(u64::MAX)));
    let held = decoded(Parent::Timeout {
        certificate: TimeoutCertificate {
            field: u64::MAX,
            quorum_certificate: quorum(12),
            votes: vec![],
        },
        quorum_certificate: None,
    });
    assert_eq!(
        first.classify_receive_order(9, Some(&held)),
        Some(ReceiveOrder::Equal(ReceivedRounds {
            incoming: u64::MAX,
            parent: u64::MAX,
            baseline: u64::MAX,
        }))
    );
}
