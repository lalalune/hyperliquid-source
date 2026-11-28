use std::io::Write;

use node115_replica_response_json::collector::{collect_full, CollectedFull, ObservedBundle};
use node115_replica_response_json::write_response;

fn emit(value: &CollectedFull<u8>) -> Vec<u8> {
    let mut output = Vec::new();
    write_response(&mut output, value.response(), |writer, entry| {
        write!(writer, "{entry}")
    })
    .unwrap();
    output
}

#[test]
fn later_end_preserves_the_already_collected_rows_even_with_an_empty_group() {
    let digest = [0x3b; 32];
    let observed = [
        ObservedBundle::Row {
            ordinal: 7,
            reference: digest,
            entries: vec![4, 9],
        },
        ObservedBundle::Row {
            ordinal: 9,
            reference: digest,
            entries: Vec::new(),
        },
        ObservedBundle::End,
        ObservedBundle::Row {
            ordinal: 10,
            reference: [0xc1; 32],
            entries: vec![8],
        },
    ];
    let prefix = collect_full(observed);
    assert_eq!(prefix.ordinals(), &[7, 9]);
    assert_eq!(prefix.stop_position(), Some(2));
    let id = "3b".repeat(32);
    assert_eq!(
        emit(&prefix),
        format!("{{\"Full\":[[\"0x{id}\",[4,9]],[\"0x{id}\",[]]]}}").as_bytes()
    );
}

#[test]
fn immediate_end_and_exhausted_input_have_the_same_json_but_distinct_evidence() {
    let observed = collect_full([ObservedBundle::End]);
    let exhausted = collect_full([]);
    assert_eq!(observed.stop_position(), Some(0));
    assert_eq!(exhausted.stop_position(), None);
    assert_eq!(emit(&observed), b"{\"Full\":[]}");
    assert_eq!(emit(&exhausted), emit(&observed));
}
