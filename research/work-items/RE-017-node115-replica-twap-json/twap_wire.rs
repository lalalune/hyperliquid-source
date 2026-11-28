use node115_replica_response_json::{
    Response,
    entry::{ActionResult, Entry, write_entry},
    write_response,
};

#[test]
fn writes_both_twap_success_and_error_shapes_in_full_rows() {
    let rows = [(
        [0; 32],
        vec![
            Entry {
                user: None,
                result: ActionResult::TwapOrder(Ok(u64::MAX)),
            },
            Entry {
                user: None,
                result: ActionResult::TwapCancel(Ok(())),
            },
            Entry {
                user: None,
                result: ActionResult::TwapOrder(Err("line\nµ")),
            },
            Entry {
                user: None,
                result: ActionResult::TwapCancel(Err("bad \"id\"")),
            },
        ],
    )];
    let mut out = Vec::new();
    write_response(&mut out, Response::Full(&rows), write_entry).unwrap();
    let expected = concat!(
        r#"{"Full":[["0x0000000000000000000000000000000000000000000000000000000000000000",["#,
        r#"{"user":null,"res":{"status":"ok","response":{"type":"twapOrder","data":{"status":{"running":{"twapId":18446744073709551615}}}}}},"#,
        r#"{"user":null,"res":{"status":"ok","response":{"type":"twapCancel","data":{"status":"success"}}}},"#,
        r#"{"user":null,"res":{"status":"ok","response":{"type":"twapOrder","data":{"status":{"error":"line\nµ"}}}}},"#,
        r#"{"user":null,"res":{"status":"ok","response":{"type":"twapCancel","data":{"status":{"error":"bad \"id\""}}}}}]]]}"#,
    );
    assert_eq!(String::from_utf8(out).unwrap(), expected);
}
