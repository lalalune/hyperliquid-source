use node115_client_block_success::{Parent, admit_timestamp, decode_payload_prefix};

fn u64v(out: &mut Vec<u8>, value: u64) {
    assert!(value <= 250);
    out.push(value as u8);
}

fn signature(out: &mut Vec<u8>) {
    for _ in 0..8 {
        u64v(out, 0);
    }
    out.push(7);
}

fn qc(out: &mut Vec<u8>, vote: bool) {
    for value in 1..=5 {
        u64v(out, value);
    }
    out.extend([0x44; 32]);
    u64v(out, u64::from(vote));
    if vote {
        out.extend([0x22; 20]);
        signature(out);
    }
}

fn header(out: &mut Vec<u8>, timeout_parent: bool, nested_qc: bool) {
    out.extend([0x11; 20]);
    u64v(out, 1);
    out.extend([0x33; 32]);
    // ZigZag(-1), then nanoseconds.
    out.extend([1, 9]);
    if timeout_parent {
        u64v(out, 1);
        u64v(out, 8);
        qc(out, false);
        u64v(out, 1);
        out.extend([0x55; 20]);
        u64v(out, 9);
        signature(out);
        out.push(u8::from(nested_qc));
        if nested_qc {
            qc(out, false);
        }
    } else {
        u64v(out, 0);
        qc(out, false);
    }
}

fn successful_payload() -> Vec<u8> {
    let mut out = Vec::new();
    u64v(&mut out, 1); // Vec<Client>
    signature(&mut out);
    header(&mut out, true, true);
    out.push(1); // Some(CommitProof)
    signature(&mut out);
    header(&mut out, false, false);
    qc(&mut out, true);
    u64v(&mut out, 1); // one attachment
    out.extend([0x66; 32]);
    u64v(&mut out, 4);
    out.extend([251, 252, 253, 255]); // opaque; not decoded as varints
    out
}

#[test]
fn parses_nested_timeout_commit_proof_votes_and_opaque_blob() {
    let mut bytes = successful_payload();
    bytes.extend([0xaa, 0xbb]);
    let outcome = decode_payload_prefix(&bytes);
    assert_eq!(outcome.remaining, &[0xaa, 0xbb]);
    let clients = outcome.result.unwrap();
    assert_eq!(clients.len(), 1);
    let client = &clients[0];
    assert_eq!(client.block.header.timestamp.second_of_day, 86_399);
    assert_eq!(client.block.header.timestamp.nanoseconds, 9);
    assert_ne!(client.block.header.timestamp.packed_date, 0);
    match &client.block.header.parent {
        Parent::Timeout {
            certificate,
            quorum_certificate: Some(extra),
        } => {
            assert_eq!(certificate.field, 8);
            assert_eq!(certificate.votes.len(), 1);
            assert_eq!(certificate.votes[0].field, 9);
            assert_eq!(extra.fields, [1, 2, 3, 4, 5]);
        }
        other => panic!("unexpected parent {other:?}"),
    }
    let proof = client.block.commit_proof.as_ref().unwrap();
    assert_eq!(proof.quorum_certificate.votes.len(), 1);
    assert_eq!(proof.header.timestamp.second_of_day, 86_399);
    assert_eq!(client.attachments[0].bytes, [251, 252, 253, 255]);
}

#[test]
fn timestamp_admission_matches_negative_epoch_and_leap_second_edges() {
    assert_eq!(admit_timestamp(-1, 0).unwrap().second_of_day, 86_399);
    assert_eq!(admit_timestamp(-86_400, 0).unwrap().second_of_day, 0);
    assert!(admit_timestamp(0, 1_000_000_000).is_err());
    assert!(admit_timestamp(59, 1_999_999_999).is_ok());
    assert!(admit_timestamp(59, 2_000_000_000).is_err());
    assert!(admit_timestamp(i64::MIN, 0).is_err());
}

#[test]
fn timestamp_leap_predicate_matches_every_second_of_day() {
    let boundaries = [
        0,
        999_999_999,
        1_000_000_000,
        1_000_000_001,
        1_999_999_999,
        2_000_000_000,
        u32::MAX,
    ];
    for second in 0..86_400_i64 {
        for nanoseconds in boundaries {
            let expected =
                nanoseconds <= 1_999_999_999 && (nanoseconds < 1_000_000_000 || second % 60 == 59);
            let actual = admit_timestamp(second, nanoseconds);
            assert_eq!(
                actual.is_ok(),
                expected,
                "second={second}, ns={nanoseconds}"
            );
            if let Ok(timestamp) = actual {
                assert_eq!(timestamp.second_of_day, second as u32);
                assert_ne!(timestamp.packed_date, 0);
            }
        }
    }
}

#[test]
fn empty_client_vector_and_proper_prefix_failures_are_safe() {
    assert_eq!(decode_payload_prefix(&[0]).result, Ok(vec![]));
    let fixture = successful_payload();
    for end in 0..fixture.len() {
        assert!(
            decode_payload_prefix(&fixture[..end]).result.is_err(),
            "prefix {end}"
        );
    }
}

#[test]
fn invalid_parent_and_option_tags_are_rejected() {
    let mut fixture = successful_payload();
    // The block header begins after Vec count and the block signature.
    let parent_tag = 1 + 9 + 20 + 1 + 32 + 1 + 1;
    fixture[parent_tag] = 2;
    assert!(decode_payload_prefix(&fixture).result.is_err());

    let mut fixture = successful_payload();
    // Locate the first timeout parent's optional-QC tag after its votes.
    let signer = fixture.windows(20).position(|w| w == [0x55; 20]).unwrap();
    let option = signer + 20 + 1 + 9;
    fixture[option] = 2;
    assert!(decode_payload_prefix(&fixture).result.is_err());
}

#[test]
fn metered_minimal_client_and_signature_reservation() {
    use node115_client_block_success::{Error, decode_payload_prefix_metered};
    let mut wire = vec![1]; // one Client
    wire.extend([0; 9]); // signature
    wire.extend([0; 20]); // header address
    wire.extend([0, 0, 0, 0]); // no hashes, timestamp zero, parent QC
    wire.extend([0; 5]); // QC scalars
    wire.extend([0; 32]); // QC hash
    wire.extend([0, 0, 0]); // no votes, proof, attachments
    assert_eq!(wire.len(), 74);
    let outcome = decode_payload_prefix_metered(&wire, Some(206), 0);
    assert!(outcome.result.is_ok());
    assert_eq!(outcome.charged, 206);
    assert!(outcome.remaining.is_empty());
    let failed = decode_payload_prefix_metered(&wire, Some(39), 0);
    assert_eq!(
        failed.result,
        Err(Error::U64(node115_u64_reader_state::Error::Limit))
    );
    assert_eq!(failed.charged, 40);
    assert_eq!(failed.remaining, &wire[1..]);
}

#[test]
fn metered_reservations_preserve_error_cursor_and_charge() {
    use node115_client_block_success::{Error, decode_payload_prefix_metered};
    use node115_u64_reader_state::Error as ReaderError;
    let no_rows = decode_payload_prefix_metered(&[0, 77], Some(8), 0);
    assert_eq!(no_rows.charged, 8);
    assert_eq!(no_rows.remaining, &[77]);
    assert_eq!(no_rows.result.unwrap().len(), 0);

    // Two client rows reserve 32 after the count; the store survives limit failure.
    let reservation = decode_payload_prefix_metered(&[2, 7], Some(39), 0);
    assert_eq!(reservation.result, Err(Error::U64(ReaderError::Limit)));
    assert_eq!(reservation.charged, 40);
    assert_eq!(reservation.remaining, &[7]);

    // A missing first signature limb retains three reserved eight-byte words.
    let short = decode_payload_prefix_metered(&[1], Some(100), 0);
    assert_eq!(
        short.result,
        Err(Error::U64(ReaderError::UnexpectedEnd { additional: 1 }))
    );
    assert_eq!(short.charged, 40);
    assert!(short.remaining.is_empty());

    // Checked charge overflow fails before storing or consuming input.
    let overflow = decode_payload_prefix_metered(&[0], Some(u64::MAX), u64::MAX - 7);
    assert_eq!(overflow.result, Err(Error::U64(ReaderError::Limit)));
    assert_eq!(overflow.charged, u64::MAX - 7);
    assert_eq!(overflow.remaining, &[0]);

    // Unlimited mode leaves the supplied counter untouched.
    let unlimited = decode_payload_prefix_metered(&[0], None, 99);
    assert!(unlimited.result.is_ok());
    assert_eq!(unlimited.charged, 99);
}

#[test]
fn metered_nested_payload_matches_existing_structure_and_suffix() {
    use node115_client_block_success::decode_payload_prefix_metered;
    let mut wire = successful_payload();
    wire.extend([0xaa, 0xbb]);
    let expected = decode_payload_prefix(&wire);
    let metered = decode_payload_prefix_metered(&wire, Some(10_000), 11);
    assert_eq!(metered.result, expected.result);
    assert_eq!(metered.remaining, &[0xaa, 0xbb]);
    // Independent field sum: 858 typed bytes plus the initial 11.
    assert_eq!(metered.charged, 869);
    let unmetered = decode_payload_prefix_metered(&wire, None, 11);
    assert_eq!(unmetered.result, expected.result);
    assert_eq!(unmetered.charged, 11);
}

#[test]
fn vector_reservation_peaks_and_count_overflow() {
    use node115_client_block_success::{Error, decode_payload_prefix_metered};
    use node115_u64_reader_state::Error as ReaderError;
    let mut qc = vec![1];
    qc.extend([0; 9 + 20 + 4 + 5 + 32]);
    assert_eq!(qc.len(), 71);
    qc.push(1);
    let peak = decode_payload_prefix_metered(&qc, Some(292), 0);
    assert_eq!(peak.result, Err(Error::U64(ReaderError::Limit)));
    assert_eq!(peak.charged, 293);
    assert!(peak.remaining.is_empty());
    qc[71] = 2;
    let short = decode_payload_prefix_metered(&qc, Some(389), 0);
    assert_eq!(short.result, Err(Error::UnexpectedEnd { additional: 20 }));
    assert_eq!(short.charged, 313);
    assert!(short.remaining.is_empty());

    let mut tc = vec![1];
    tc.extend([0; 9 + 20]);
    tc.extend([0, 0, 0, 1, 0]); // hash count, timestamp, TC parent, TC field
    tc.extend([0; 5 + 32 + 1]); // embedded QC, no QC votes
    assert_eq!(tc.len(), 73);
    tc.push(1); // one TC vote
    let peak = decode_payload_prefix_metered(&tc, Some(316), 0);
    assert_eq!(peak.result, Err(Error::U64(ReaderError::Limit)));
    assert_eq!(peak.charged, 317);
    assert!(peak.remaining.is_empty());

    let mut huge = vec![253];
    huge.extend(u64::MAX.to_le_bytes());
    let overflow = decode_payload_prefix_metered(&huge, Some(u64::MAX), 0);
    assert_eq!(overflow.result, Err(Error::U64(ReaderError::Limit)));
    assert_eq!(overflow.charged, 8);
    assert!(overflow.remaining.is_empty());
}

#[test]
fn metered_invalid_proof_option_consumes_tag_and_keeps_charge() {
    use node115_client_block_success::{Error, decode_payload_prefix_metered};
    let mut wire = vec![1];
    wire.extend([0; 9 + 20 + 4 + 5 + 32 + 1]); // signature, header, empty QC votes
    assert_eq!(wire.len(), 72);
    wire.extend([2, 0xaa]);
    let outcome = decode_payload_prefix_metered(&wire, Some(1000), 0);
    assert_eq!(outcome.result, Err(Error::InvalidOption(2)));
    assert_eq!(outcome.charged, 198);
    assert_eq!(outcome.remaining, &[0xaa]);
}

fn replay_block(option: u8) -> Vec<u8> {
    let mut input = vec![0];
    signature(&mut input);
    header(&mut input, false, false);
    input.extend([0, option]); // no commit proof, then replay attachment option
    input
}

#[test]
fn replay_block_distinguishes_absent_empty_and_populated_attachments() {
    use node115_client_block_success::{ReplayPayload, decode_replay_payload_prefix};

    let mut absent = replay_block(0);
    absent.push(0xee);
    let plain = decode_replay_payload_prefix(&absent, 10_000_000);
    assert_eq!(plain.remaining, &[0xee]);
    let ReplayPayload::Block {
        block,
        attachments: None,
    } = plain.result.unwrap()
    else {
        panic!("expected Block with absent attachments");
    };
    assert_eq!(block.header.address, [0x11; 20]);
    let projected = node115_client_block_success::replay_parent_projection(&block.header.parent);
    assert_eq!(
        (projected.comparison_words, projected.successor),
        ([1, 2], 4)
    );

    let mut empty = replay_block(1);
    empty.extend([0, 0xee]);
    let empty_result = decode_replay_payload_prefix(&empty, 10_000_000);
    assert_eq!(empty_result.remaining, &[0xee]);
    assert_eq!(empty_result.charged, plain.charged + 8);
    assert_eq!(
        empty_result.result.unwrap(),
        ReplayPayload::Block {
            block: block.clone(),
            attachments: Some(vec![]),
        }
    );

    let mut one = replay_block(1);
    one.push(1);
    one.extend([0x66; 32]);
    one.extend([3, 251, 252, 255, 0xee]);
    let decoded = decode_replay_payload_prefix(&one, 10_000_000);
    assert_eq!(decoded.remaining, &[0xee]);
    let ReplayPayload::Block {
        block: decoded_block,
        attachments: Some(rows),
    } = decoded.result.unwrap()
    else {
        panic!("expected Block with attachments")
    };
    assert_eq!(decoded_block, block);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].hash, [0x66; 32]);
    assert_eq!(rows[0].bytes, [251, 252, 255]);
    assert_eq!(decoded.charged, plain.charged + 51);
}

#[test]
fn replay_tx_is_opaque_and_preserves_the_suffix_at_equal_budget() {
    use node115_client_block_success::{ReplayPayload, decode_replay_payload_prefix};

    let decode = decode_replay_payload_prefix(&[1, 3, 251, 252, 255, 0xee], 15);
    assert_eq!(decode.result, Ok(ReplayPayload::Tx(vec![251, 252, 255])));
    assert_eq!(decode.remaining, &[0xee]);
    assert_eq!(decode.charged, 15);
    let empty = decode_replay_payload_prefix(&[1, 0, 0xee], 12);
    assert_eq!(empty.result, Ok(ReplayPayload::Tx(vec![])));
    assert_eq!(empty.remaining, &[0xee]);
}

#[test]
fn replay_rejects_unknown_variants_options_and_incomplete_blobs() {
    use node115_client_block_success::{Error, ReplayError, decode_replay_payload_prefix};

    let tag = decode_replay_payload_prefix(&[2, 0xee], 100);
    assert_eq!(tag.result, Err(ReplayError::InvalidTag(2)));
    assert_eq!((tag.remaining, tag.charged), (&[0xee][..], 4));
    let mut invalid = replay_block(2);
    invalid.push(0xee);
    let option = decode_replay_payload_prefix(&invalid, 10_000_000);
    assert_eq!(
        option.result,
        Err(ReplayError::Decode(Error::InvalidOption(2)))
    );
    assert_eq!(option.remaining, &[0xee]);

    let short = decode_replay_payload_prefix(&[1, 3, 0x55], 15);
    assert_eq!(
        short.result,
        Err(ReplayError::Decode(Error::UnexpectedEnd { additional: 2 }))
    );
    assert_eq!((short.remaining, short.charged), (&[0x55][..], 15));
    let limit = decode_replay_payload_prefix(&[1, 3, 0x55], 14);
    assert!(matches!(
        limit.result,
        Err(ReplayError::Decode(Error::U64(_)))
    ));
    assert_eq!((limit.remaining, limit.charged), (&[0x55][..], 15));
}

#[test]
fn replay_parent_projection_selects_each_certificate_path() {
    use node115_client_block_success::{
        QuorumCertificate, ReplayParentProjection, TimeoutCertificate, replay_parent_projection,
    };

    let direct = QuorumCertificate {
        fields: [101, 102, 103, 104, 105],
        hash: [0; 32],
        votes: vec![],
    };
    let nested = QuorumCertificate {
        fields: [201, 202, 203, 204, 205],
        ..direct.clone()
    };
    let certificate = TimeoutCertificate {
        field: 300,
        quorum_certificate: direct.clone(),
        votes: vec![],
    };

    assert_eq!(
        replay_parent_projection(&Parent::QuorumCertificate(direct.clone())),
        ReplayParentProjection {
            comparison_words: [101, 102],
            successor: 104
        },
    );
    assert_eq!(
        replay_parent_projection(&Parent::Timeout {
            certificate: certificate.clone(),
            quorum_certificate: None
        }),
        ReplayParentProjection {
            comparison_words: [101, 102],
            successor: 301
        },
    );
    assert_eq!(
        replay_parent_projection(&Parent::Timeout {
            certificate,
            quorum_certificate: Some(nested)
        }),
        ReplayParentProjection {
            comparison_words: [201, 202],
            successor: 301
        },
    );
    let mut maximum = direct;
    maximum.fields[2] = u64::MAX;
    assert_eq!(
        replay_parent_projection(&Parent::QuorumCertificate(maximum)).successor,
        u64::MAX
    );
}
