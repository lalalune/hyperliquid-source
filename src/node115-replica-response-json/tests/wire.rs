use node115_replica_response_json::{write_response, Response};
use std::io::{self, Write};

#[test]
fn writes_null_hash_and_ordered_full_rows() {
    let mut out = Vec::new();
    write_response::<_, ()>(&mut out, Response::Null, |_, _| unreachable!()).unwrap();
    assert_eq!(out, b"null");
    out.clear();
    let mut h = [0; 32];
    h[0] = 0xab;
    h[31] = 0xff;
    write_response::<_, ()>(&mut out, Response::Hash(&h), |_, _| unreachable!()).unwrap();
    assert_eq!(
        String::from_utf8(out).unwrap(),
        format!("{{\"Hash\":\"0xab{}ff\"}}", "00".repeat(30))
    );
    let rows = [(h, vec![7u8, 9]), ([0; 32], vec![])];
    let mut out = Vec::new();
    write_response(&mut out, Response::Full(&rows), |w, n| write!(w, "{n}")).unwrap();
    assert_eq!(
        String::from_utf8(out).unwrap(),
        format!(
            "{{\"Full\":[[\"0xab{}ff\",[7,9]],[\"0x{}\",[]]]}}",
            "00".repeat(30),
            "00".repeat(32)
        )
    );
}

#[test]
fn child_failure_keeps_prefix_and_skips_later_entries() {
    let rows = [([0; 32], vec![1, 2])];
    let mut out = Vec::new();
    let mut calls = 0;
    let err = write_response(&mut out, Response::Full(&rows), |w, _| {
        calls += 1;
        w.write_all(b"partial")?;
        Err(io::Error::other("child"))
    })
    .unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::Other);
    assert_eq!(calls, 1);
    assert!(out.ends_with(b",[partial"));
    assert!(!out.ends_with(b"]}"));
}
