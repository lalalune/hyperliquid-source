use node115_client_block_success::{
    ReplayPayload, RetainedParentLink, decode_replay_payload_prefix, replay_parent_projection,
    replay_retained_parent_link,
};

const DIRECT: [u8; 32] = [
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
];
const EMBEDDED: [u8; 32] = [
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
];
const OPTIONAL: [u8; 32] = [
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
    0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
];

fn quorum(wire: &mut Vec<u8>, identity: u8, hash: [u8; 32]) {
    wire.extend([1, 2, identity, 4, 5]);
    wire.extend(hash);
    wire.push(0); // votes
}

fn decoded_operands(parent: &[u8]) -> (RetainedParentLink, u64) {
    let mut wire = vec![0; 10]; // Block tag and signature placeholder
    wire.extend([0x72; 20]); // proposer
    wire.extend([1]); // one header digest, separate from the QC hash
    wire.extend([0x7a; 32]);
    wire.extend([0, 7]); // timestamp
    wire.extend(parent);
    wire.extend([0, 0]); // omitted proof and omitted attachments
    let decoded = decode_replay_payload_prefix(&wire, 10_000_000);
    assert!(decoded.remaining.is_empty());
    let Ok(ReplayPayload::Block { block, .. }) = decoded.result else {
        panic!("expected Block")
    };
    (
        replay_retained_parent_link(&block.header.parent),
        replay_parent_projection(&block.header.parent).successor,
    )
}

#[test]
fn direct_quorum_predecessor_comes_from_its_raw_hash() {
    let mut parent = vec![0];
    quorum(&mut parent, 23, DIRECT);
    assert_eq!(
        decoded_operands(&parent),
        (
            RetainedParentLink {
                identity: 23,
                predecessor: DIRECT,
            },
            24,
        ),
    );
}

#[test]
fn embedded_quorum_predecessor_leaves_timeout_successor_separate() {
    let mut parent = vec![1, 90];
    quorum(&mut parent, 31, EMBEDDED);
    parent.extend([0, 0]); // timeout votes and absent extra quorum
    assert_eq!(
        decoded_operands(&parent),
        (
            RetainedParentLink {
                identity: 31,
                predecessor: EMBEDDED,
            },
            91,
        ),
    );
}

#[test]
fn optional_quorum_supplies_both_incoming_operands() {
    let mut parent = vec![1, 92];
    quorum(&mut parent, 31, EMBEDDED);
    parent.extend([0, 1]); // timeout votes and present extra quorum
    quorum(&mut parent, 41, OPTIONAL);
    assert_eq!(
        decoded_operands(&parent),
        (
            RetainedParentLink {
                identity: 41,
                predecessor: OPTIONAL,
            },
            93,
        ),
    );
}
