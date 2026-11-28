use node115_replay_completed_payload::conversion::{
    ConversionCursor, ConversionOutcome, PreparedRecord,
};

fn record(identity: u64, attachment_count: u64) -> PreparedRecord {
    PreparedRecord {
        identity,
        successor: identity.saturating_add(1),
        attachment_count,
    }
}

#[test]
fn empty_records_move_identity_until_the_first_eligible_parent_round() {
    let mut cursor = ConversionCursor::from_restored_round(100);
    for identity in 100..109 {
        assert_eq!(
            cursor.observe(record(identity, 0)),
            ConversionOutcome::EmptyRecordSkipped
        );
        assert_eq!(cursor.expected_identity(), identity + 1);
        assert_eq!(cursor.cutoff(), 100);
    }

    assert_eq!(
        cursor.observe(record(109, 0)),
        ConversionOutcome::Converted { parent_round: 100 }
    );
    assert_eq!(cursor.expected_identity(), 110);
    assert_eq!(cursor.cutoff(), 110);
    assert_eq!(
        cursor.observe(record(110, 1)),
        ConversionOutcome::Converted { parent_round: 110 }
    );
    assert_eq!(cursor.expected_identity(), 111);
    assert_eq!(cursor.cutoff(), 111);
}

#[test]
fn nonempty_prepared_owner_bypasses_gate_before_filtering() {
    let mut cursor = ConversionCursor::from_restored_round(100);
    assert_eq!(
        cursor.observe(record(100, 1)),
        ConversionOutcome::Converted { parent_round: 100 }
    );
    assert_eq!(cursor.cutoff(), 101);
}

#[test]
fn saturating_threshold_preserves_the_exact_boundary() {
    let start = u64::MAX - 2;
    let mut cursor = ConversionCursor::from_restored_round(start);
    assert_eq!(
        cursor.observe(record(start, 0)),
        ConversionOutcome::EmptyRecordSkipped
    );
    assert_eq!(
        cursor.observe(record(start + 1, 0)),
        ConversionOutcome::Converted {
            parent_round: start
        }
    );
    assert_eq!(cursor.expected_identity(), u64::MAX);
    assert_eq!(cursor.cutoff(), u64::MAX);
}

#[test]
fn mismatch_does_not_change_either_round() {
    let mut cursor = ConversionCursor::from_restored_round(100);
    cursor.observe(record(100, 0));
    let prior = cursor;
    assert_eq!(
        cursor.observe(record(102, 1)),
        ConversionOutcome::IdentityMismatch {
            expected: 101,
            observed: 102,
        }
    );
    assert_eq!(cursor, prior);
}

#[test]
fn successor_can_differ_from_identity_increment() {
    let mut cursor = ConversionCursor::from_restored_round(100);
    assert_eq!(
        cursor.observe(PreparedRecord {
            identity: 100,
            successor: 112,
            attachment_count: 0,
        }),
        ConversionOutcome::Converted { parent_round: 100 }
    );
    assert_eq!(cursor.expected_identity(), 112);
    assert_eq!(cursor.cutoff(), 112);
}

#[test]
fn decoded_quorum_records_keep_the_first_archive_parent_round() {
    use node115_client_block_success::{replay_parent_projection, Parent};
    use node115_replay_completed_payload::{
        decode_completed_payload, CompletedPayload, ReplayPayload,
    };

    let mut cursor = ConversionCursor::from_restored_round(100);
    for identity in 100..=109 {
        let mut wire = vec![0; 10]; // Block tag and signature
        wire.extend([0x31; 20]); // proposer
        wire.extend([0, 0, 7, 0]); // hashes, timestamp, quorum parent
        wire.extend([1, 2, identity, 4, 5]); // quorum-certificate fields
        wire.extend([0x71; 32]); // quorum hash
        wire.extend([0, 0, 1, 0]); // votes, omitted proof, present empty attachments
        let decoded = decode_completed_payload(CompletedPayload::Plain(&wire)).unwrap();
        let Ok(ReplayPayload::Block {
            block,
            attachments: Some(attachments),
        }) = &decoded.result
        else {
            panic!("expected Block with a present empty attachment vector");
        };
        let Parent::QuorumCertificate(quorum) = &block.header.parent else {
            panic!("expected quorum parent");
        };
        assert!(attachments.is_empty());
        let outcome = cursor.observe(PreparedRecord {
            identity: quorum.fields[2],
            successor: replay_parent_projection(&block.header.parent).successor,
            attachment_count: 0,
        });
        if identity != 109 {
            assert_eq!(outcome, ConversionOutcome::EmptyRecordSkipped);
            continue;
        }
        let ConversionOutcome::Converted { parent_round } = outcome else {
            panic!("the threshold record should convert");
        };
        assert_eq!(parent_round, 100);
        assert_eq!(replay_parent_projection(&block.header.parent).successor, 110);
        assert_eq!(cursor.cutoff(), 110);
    }
}
