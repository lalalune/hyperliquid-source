use node115_replica_response_json::entry::{write_entry, ActionResult, Entry};
use node115_replica_response_json::{write_response, Response};

#[test]
fn full_rows_emit_native_entry_fields_and_lowercase_escapes() {
    let mut user = [0; 20];
    user[19] = 0xaf;
    let rows = [(
        [0x45; 32],
        vec![
            Entry {
                user: Some(user),
                result: ActionResult::Error("\"\\/é\n\t\u{001f}"),
            },
            Entry {
                user: None,
                result: ActionResult::Default,
            },
        ],
    )];
    let mut output = Vec::new();
    write_response(&mut output, Response::Full(&rows), write_entry).unwrap();
    let expected = format!(
        concat!(
            "{{\"Full\":[[\"0x{}\",[",
            "{{\"user\":\"0x{}af\",\"res\":{{\"status\":\"err\",\"response\":\"\\\"\\\\/é\\n\\t\\u001f\"}}}},",
            "{{\"user\":null,\"res\":{{\"status\":\"ok\",\"response\":{{\"type\":\"default\"}}}}}}]]",
            "]}}"
        ),
        "45".repeat(32),
        "00".repeat(19),
    );
    assert_eq!(output, expected.as_bytes());
}

#[test]
fn selected_success_labels_remain_distinct_and_numbers_are_unsigned() {
    for (result, expected) in [
        (
            ActionResult::ValidatorVote(false),
            r#"{"type":"validatorVote","data":false}"#,
        ),
        (
            ActionResult::ValidatorVote(true),
            r#"{"type":"validatorVote","data":true}"#,
        ),
        (
            ActionResult::Token(u64::MAX),
            r#"{"type":"token","data":18446744073709551615}"#,
        ),
        (ActionResult::Spot(42), r#"{"type":"spot","data":42}"#),
    ] {
        let mut output = Vec::new();
        write_entry(&mut output, &Entry { user: None, result }).unwrap();
        assert_eq!(
            output,
            format!("{{\"user\":null,\"res\":{{\"status\":\"ok\",\"response\":{expected}}}}}")
                .as_bytes(),
        );
    }
}
