use std::io::{self, Write};

use node115_replica_response_json::{
    MissingPeriodicHash, Response, select_response, write_response,
};

fn emit(response: Response<'_, u8>) -> Vec<u8> {
    let mut text = Vec::new();
    write_response(&mut text, response, |output, value| -> io::Result<()> {
        write!(output, "{value}")
    })
    .unwrap();
    text
}

#[test]
fn non_full_lane_emits_only_the_periodic_hash_at_adjacent_heights() {
    let hash = [0xab; 32];
    let mut outputs = Vec::new();
    for height in 98..=100 {
        outputs.push(emit(select_response(0, height, &[], Some(&hash)).unwrap()));
    }
    assert_eq!(outputs[0], b"null");
    assert_eq!(
        outputs[1],
        format!("{{\"Hash\":\"0x{}\"}}", "ab".repeat(32)).as_bytes()
    );
    assert_eq!(outputs[2], b"null");
}

#[test]
fn full_lane_selects_rows_even_at_a_hash_height() {
    let rows = [([0x8d; 32], vec![7, 9]), ([0x91; 32], vec![])];
    let expected = format!(
        "{{\"Full\":[[\"0x{}\",[7,9]],[\"0x{}\",[]]]}}",
        "8d".repeat(32),
        "91".repeat(32)
    );
    assert_eq!(
        emit(select_response(1, 99, &rows, Some(&[0xab; 32])).unwrap()),
        expected.as_bytes()
    );
    assert_eq!(
        emit(select_response(1, 100, &rows, None).unwrap()),
        expected.as_bytes()
    );
}

#[test]
fn unavailable_periodic_reference_does_not_become_null() {
    assert!(matches!(
        select_response::<()>(2, 99, &[], None),
        Err(MissingPeriodicHash { post_height: 99 })
    ));
    assert!(matches!(
        select_response::<()>(2, 100, &[], None),
        Ok(Response::Null)
    ));
    assert!(matches!(
        select_response::<()>(1, 99, &[], None),
        Ok(Response::Full([]))
    ));
}
