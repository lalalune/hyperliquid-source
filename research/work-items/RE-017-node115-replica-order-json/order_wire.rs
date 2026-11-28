use node115_replica_response_json::{
    Response,
    entry::{ActionResult, Entry, write_entry},
    order::OrderStatus,
    write_response,
};

#[test]
fn compact_full_order_status_bytes() {
    let mut cloid = [0; 16];
    cloid[15] = 0xaf;
    let statuses = [
        OrderStatus::Filled {
            total_size: "0.0",
            average_price: "12.5",
            order_id: 128,
            client_order_id: Some(cloid),
        },
        OrderStatus::WaitingForFill,
        OrderStatus::Resting {
            order_id: u64::MAX,
            client_order_id: None,
        },
        OrderStatus::WaitingForTrigger,
        OrderStatus::Error("bad\n\"price µ"),
    ];
    let rows = [(
        [0x5a; 32],
        vec![
            Entry {
                user: None,
                result: ActionResult::Order(&statuses),
            },
            Entry {
                user: Some([0x7c; 20]),
                result: ActionResult::Default,
            },
        ],
    )];
    let mut out = Vec::new();
    write_response(&mut out, Response::Full(&rows), write_entry).unwrap();
    let expected = concat!(
        r#"{"Full":[["0x5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a",["#,
        r#"{"user":null,"res":{"status":"ok","response":{"type":"order","data":{"statuses":["#,
        r#"{"filled":{"totalSz":"0.0","avgPx":"12.5","oid":128,"cloid":"0x000000000000000000000000000000af"}},"#,
        r#""waitingForFill",{"resting":{"oid":18446744073709551615}},"waitingForTrigger",{"error":"bad\n\"price µ"}]}}}},"#,
        r#"{"user":"0x7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c","res":{"status":"ok","response":{"type":"default"}}}]]]}"#,
    );
    assert_eq!(String::from_utf8(out).unwrap(), expected);
}

#[test]
fn empty_order_list_still_has_data_and_statuses() {
    let mut out = Vec::new();
    write_entry(
        &mut out,
        &Entry {
            user: None,
            result: ActionResult::Order(&[]),
        },
    )
    .unwrap();
    assert_eq!(out, br#"{"user":null,"res":{"status":"ok","response":{"type":"order","data":{"statuses":[]}}}}"#);
}
