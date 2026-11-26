use node115_gossip_response_composed::{Error, Response, decode_prefix};
use node115_gossip_response_v2_envelope as outer;
use node115_u32_varint::ReadError;

#[test]
fn raw_one_is_address_vector_and_retains_suffix() {
    let out = decode_prefix(&[1, 0, 0xee], Some(12), 0);
    assert_eq!(out.result, Ok(Response::Addresses(vec![])));
    assert_eq!(out.remaining, &[0xee]);
    assert_eq!(out.charged, 12);
}
#[test]
fn raw_zero_nested_error_uses_existing_decoder() {
    let out = decode_prefix(&[0, 1, 1, 5, 7, 0xee], Some(28), 0);
    match out.result {
        Ok(Response::ClientBlocksError(value)) => {
            assert_eq!(value.index, 1);
            assert_eq!(value.fields, Some([5, 7]));
        }
        other => panic!("unexpected {other:?}"),
    }
    assert_eq!(out.remaining, &[0xee]);
    assert_eq!(out.charged, 28);
}
#[test]
fn limited_success_remains_an_explicit_budget_boundary() {
    let out = decode_prefix(&[0, 0, 42, 43], Some(8), 0);
    assert_eq!(out.result, Ok(Response::ResultSuccessBoundary));
    assert_eq!(out.remaining, &[42, 43]);
    assert_eq!(out.charged, 8);
}

fn empty_client_payload() -> Vec<u8> {
    let mut wire = vec![0, 0, 1]; // outer tag 0, Result::Ok tag 0, one Client
    wire.extend([0; 9]); // signature: eight zero limbs and recovery byte
    wire.extend([0; 20]); // Header address
    wire.push(0); // Header hashes
    wire.extend([0, 0, 0]); // timestamp seconds, nanos, QC parent tag
    wire.extend([0; 5]); // QC scalar fields
    wire.extend([0; 32]); // QC hash
    wire.push(0); // QC votes
    wire.push(0); // no commit proof
    wire.push(0); // no attachments
    wire
}

#[test]
fn unlimited_nested_success_uses_real_clientblocks_decoder_and_retains_suffix() {
    let mut wire = empty_client_payload();
    wire.extend([0xee, 0xff]);
    let out = decode_prefix(&wire, None, 17);
    assert_eq!(out.result, Ok(Response::ClientBlocks(vec![
        node115_client_block_success::Client {
            block: node115_client_block_success::Block {
                signature: node115_client_block_success::Signature {
                    limbs: [0; 8],
                    recovery: 0,
                },
                header: node115_client_block_success::Header {
                    address: [0; 20],
                    hashes: vec![],
                    timestamp: node115_client_block_success::AdmittedTimestamp {
                        packed_date: 16138266,
                        second_of_day: 0,
                        nanoseconds: 0,
                    },
                    parent: node115_client_block_success::Parent::QuorumCertificate(
                        node115_client_block_success::QuorumCertificate {
                            fields: [0; 5],
                            hash: [0; 32],
                            votes: vec![],
                        },
                    ),
                },
                commit_proof: None,
            },
            attachments: vec![],
        },
    ])));
    assert_eq!(out.remaining, &[0xee, 0xff]);
    assert_eq!(out.charged, 17);
}

#[test]
fn unlimited_nested_success_maps_child_parse_error() {
    let out = decode_prefix(&[0, 0, 1, 0], None, 0);
    assert!(matches!(out.result, Err(Error::ClientBlocksSuccess(_))));
}
#[test]
fn variant_two_is_forwarded_without_double_tag() {
    let out = decode_prefix(&[2, 0, 0xee], Some(5), 0);
    assert_eq!(out.result, Ok(Response::Variant2(None)));
    assert_eq!(out.remaining, &[0xee]);
    assert_eq!(out.charged, 5);
}
#[test]
fn outer_and_nested_invalid_tags_are_distinct() {
    let outer_result = decode_prefix(&[3, 0xaa], None, 0);
    assert_eq!(
        outer_result.result,
        Err(Error::Outer(outer::Error::InvalidVariant { index: 3 }))
    );
    assert_eq!(outer_result.remaining, &[0xaa]);
    let nested = decode_prefix(&[0, 2, 0xaa], None, 0);
    assert_eq!(nested.result, Err(Error::InvalidResultTag(2)));
    assert_eq!(nested.remaining, &[0xaa]);
}
#[test]
fn nested_limit_keeps_prior_cursor_and_post_charge() {
    let out = decode_prefix(&[0, 1, 0], Some(7), 0);
    assert_eq!(out.result, Err(Error::ResultTag(ReadError::Limit)));
    assert_eq!(out.remaining, &[1, 0]);
    assert_eq!(out.charged, 8);
}
#[test]
fn nested_short_marker_retains_slow_path_progress() {
    let out = decode_prefix(&[0, 251, 1], None, 0);
    assert_eq!(
        out.result,
        Err(Error::ResultTag(ReadError::UnexpectedEnd { additional: 1 }))
    );
    assert_eq!(out.remaining, &[1]);
}

#[test]
fn nonempty_vector_uses_real_element_decoder() {
    let out = decode_prefix(&[1, 1, 0, 1, 2, 3, 4, 1, 5, 0xee], Some(36), 0);
    match out.result {
        Ok(Response::Addresses(values)) => {
            assert_eq!(values.len(), 1);
            assert_eq!(values[0].fixed, 0x04030201);
            assert!(values[0].flag);
            assert_eq!(values[0].value, 5);
        }
        other => panic!("unexpected {other:?}"),
    }
    assert_eq!(out.remaining, &[0xee]);
    assert_eq!(out.charged, 25);
}

#[test]
fn vector_precharge_refuses_before_consuming_element() {
    let out = decode_prefix(&[1, 1, 0, 1, 2, 3, 4, 1, 5], Some(35), 0);
    assert!(matches!(out.result, Err(Error::Addresses(_))));
    assert_eq!(out.remaining, &[0, 1, 2, 3, 4, 1, 5]);
    assert_eq!(out.charged, 36);
}

#[test]
fn nested_error_all_seven_variants_have_expected_payloads() {
    for tag in 0..=6u8 {
        let mut wire = vec![0, 1, tag];
        if matches!(tag, 1 | 5 | 6) {
            wire.extend([7, 9]);
        }
        wire.push(0xee);
        let result = decode_prefix(&wire, None, 0);
        match result.result {
            Ok(Response::ClientBlocksError(value)) => {
                assert_eq!(value.index, u32::from(tag));
                assert_eq!(
                    value.fields,
                    if matches!(tag, 1 | 5 | 6) {
                        Some([7, 9])
                    } else {
                        None
                    }
                );
            }
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(result.remaining, &[0xee]);
    }
}

#[test]
fn partial_nested_error_keeps_child_progress() {
    let out = decode_prefix(&[0, 1, 1, 5], None, 0);
    assert!(matches!(out.result, Err(Error::ClientBlocksError(_))));
    assert_eq!(out.remaining, &[]);
}

#[test]
fn selected_success_composes_budget_and_retains_suffix() {
    use node115_gossip_response_composed::{ComposedResponse, decode_prefix_with_success};
    let input = [0, 0, 0, 0xaa]; // outer result, success, empty client vector
    let value = decode_prefix_with_success(&input, Some(16), 0);
    assert_eq!(
        value.result,
        Ok(ComposedResponse::ClientBlocksSuccess(Vec::new()))
    );
    assert_eq!(value.charged, 16); // two U32 tags + one U64 count
    assert_eq!(value.remaining, &[0xaa]);
    let failure = decode_prefix_with_success(&input, Some(15), 0);
    assert!(failure.result.is_err());
    assert_eq!(failure.charged, 16);
    assert_eq!(failure.remaining, &input[2..]);
}
