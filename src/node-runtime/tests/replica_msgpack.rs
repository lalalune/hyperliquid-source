use node_runtime::stream_msg::{Date, Time};
use node_runtime::{ReplicaStreamRecord, SharedStreamMsg};

#[test]
fn emits_named_replica_envelope_and_shares_the_encoded_buffer() {
    let record = ReplicaStreamRecord {
        date: Date::new(2024, 60).unwrap(),
        time: Time::new(0, 0).unwrap(),
        encoded_bundles: &[&[1], &[0x81, 0xa1, b'x', 0xc2]],
        round: 128,
        parent_round: 127,
        hardfork_version: 1,
        hardfork_round: 0,
        proposer: [0xac; 20],
        encoded_responses: None,
        height: 65_536,
    };
    let message = SharedStreamMsg::from_replica_record(&record).unwrap();
    let block: &[&[u8]] = &[
        b"\x83\xaaabci_block\x86\xa4time\xb32024-02-29T00:00:00",
        b"\xb5signed_action_bundles\x92\x01\x81\xa1x\xc2",
        b"\xa5round\xcc\x80\xacparent_round\x7f",
        b"\xa8hardfork\x82\xa7version\x01\xa5round\x00",
        b"\xa8proposer\xd9\x2a0xacacacacacacacacacacacacacacacacacacacac",
        b"\xa5resps",
    ];
    let mut expected = block.concat();
    expected.extend_from_slice(b"\xc0\xa6height\xce\x00\x01\x00\x00");
    assert_eq!(message.as_bytes(), expected);
    let shared = message.clone();
    assert_eq!(message.strong_count(), 2);
    assert!(std::ptr::eq(message.as_bytes(), shared.as_bytes()));

    let present = ReplicaStreamRecord {
        encoded_responses: Some(b"\x91\xa2ok"),
        ..record
    };
    let mut expected = block.concat();
    expected.extend_from_slice(b"\x91\xa2ok\xa6height\xce\x00\x01\x00\x00");
    let message = SharedStreamMsg::from_replica_record(&present).unwrap();
    assert_eq!(message.as_bytes(), expected);
}
