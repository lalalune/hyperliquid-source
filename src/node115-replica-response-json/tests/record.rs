use std::io::{self, Write};

use node115_replica_response_json::record::{write_record, Bundle, Header, Record};
use node115_replica_response_json::Response;

fn header() -> Header<'static> {
    Header {
        time: "2026-10-31T00:00:00.000000123",
        round: 901,
        parent_round: 899,
        hardfork_version: 1,
        hardfork_round: 35,
        proposer: [0x12; 20],
    }
}

#[test]
fn emits_exact_native_line_order_and_separate_unsigned_coordinates() {
    let broadcaster = [0u8; 20];
    let bundles = [
        Bundle {
            reference: [0x04; 32],
            signed_actions: vec![r#"{"nonce":7}"#, r#"{"nonce":8}"#],
            broadcaster,
            broadcaster_nonce: u64::MAX,
        },
        Bundle {
            reference: [0x56; 32],
            signed_actions: vec![],
            broadcaster,
            broadcaster_nonce: 7,
        },
    ];
    let responses = [(
        [0x04; 32],
        vec![r#"{"user":null,"res":{"status":"ok","response":{"type":"default"}}}"#],
    )];
    let record = Record {
        header: header(),
        bundles: &bundles,
        responses: Response::Full(&responses),
        height: 30,
    };
    let mut output = Vec::new();
    write_record(
        &mut output,
        record,
        |w, action| w.write_all(action.as_bytes()),
        |w, result| w.write_all(result.as_bytes()),
    )
    .unwrap();
    let expected = format!(
        concat!(
            "{{\"abci_block\":{{\"time\":\"2026-10-31T00:00:00.000000123\",\"signed_action_bundles\":[",
            "[\"0x{}\",{{\"signed_actions\":[{{\"nonce\":7}},{{\"nonce\":8}}],",
            "\"broadcaster\":\"0x{}\",\"broadcaster_nonce\":18446744073709551615}}],",
            "[\"0x{}\",{{\"signed_actions\":[],\"broadcaster\":\"0x{}\",\"broadcaster_nonce\":7}}]",
            "],\"round\":901,\"parent_round\":899,\"hardfork\":{{\"version\":1,\"round\":35}},\"proposer\":\"0x{}\"}},",
            "\"resps\":{{\"Full\":[[\"0x{}\",[{{\"user\":null,\"res\":{{\"status\":\"ok\",\"response\":{{\"type\":\"default\"}}}}}}]]]}},",
            "\"height\":30}}\n"
        ),
        "04".repeat(32), "00".repeat(20), "56".repeat(32), "00".repeat(20), "12".repeat(20), "04".repeat(32),
    );
    assert_eq!(output, expected.as_bytes());
}

#[test]
fn null_response_and_empty_bundle_array_remain_explicit() {
    let mut output = Vec::new();
    let record = Record::<(), ()> {
        header: header(),
        bundles: &[],
        responses: Response::Null,
        height: 31,
    };
    write_record(
        &mut output,
        record,
        |_, _| unreachable!(),
        |_, _| unreachable!(),
    )
    .unwrap();
    let text = std::str::from_utf8(&output).unwrap();
    assert!(text.contains(r#""signed_action_bundles":[],"round":901"#));
    assert!(text.ends_with("\"resps\":null,\"height\":31}\n"));
}

#[test]
fn entry_error_leaves_one_prefix_and_bypasses_later_entries() {
    let mut calls = 0;
    let mut output = Vec::new();
    let bundles = [Bundle {
        reference: [0; 32],
        signed_actions: vec![1, 2],
        broadcaster: [0; 20],
        broadcaster_nonce: 0,
    }];
    let record = Record::<_, ()> {
        header: header(),
        bundles: &bundles,
        responses: Response::Null,
        height: 31,
    };
    let error = write_record(
        &mut output,
        record,
        |_, _| {
            calls += 1;
            Err(io::ErrorKind::Interrupted.into())
        },
        |_, _| unreachable!(),
    )
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::Interrupted);
    assert_eq!(calls, 1);
    assert!(output.ends_with(b"\"signed_actions\":["));
}
