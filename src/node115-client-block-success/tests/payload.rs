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
