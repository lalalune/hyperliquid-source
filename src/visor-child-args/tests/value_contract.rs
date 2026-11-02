use visor_child_args::{CollectError, collect_child_args, native_descriptor_bytes};

#[test]
fn descriptor_integer_domain_is_checked_without_allocating() {
    let last = i64::MAX as u64 / 24;
    assert_eq!(native_descriptor_bytes(0), Some(0));
    assert_eq!(native_descriptor_bytes(4), Some(96));
    assert_eq!(native_descriptor_bytes(last), Some(i64::MAX as u64 - 7));
    assert_eq!(native_descriptor_bytes(last + 1), None);
    assert_eq!(native_descriptor_bytes(1 << 63), None);
    assert_eq!(native_descriptor_bytes(u64::MAX), None);
}

#[test]
fn no_descriptors_and_null_empty_stop_produce_no_values() {
    assert!(collect_child_args(&[]).unwrap().is_empty());
    assert!(
        collect_child_args(&[None, Some(&[0xff])])
            .unwrap()
            .is_empty()
    );
}

#[test]
fn nonnull_empty_is_an_element_and_does_not_stop() {
    let items = [Some(&b""[..]), Some(&b"a"[..]), Some(&b""[..]), None];
    assert_eq!(collect_child_args(&items).unwrap(), ["", "a", ""]);
}

#[test]
fn original_utf8_nul_quotes_and_whitespace_bytes_survive() {
    let a = b" a\t\0'\"^/";
    let b = [0xf4, 0x8f, 0xbf, 0xbf];
    let values = collect_child_args(&[Some(a), Some(&b)]).unwrap();
    assert_eq!(values[0].as_bytes(), a);
    assert_eq!(values[1].as_bytes(), b);
}

#[test]
fn invalid_utf8_refusal_is_first_argument_only() {
    for bad in [
        &b"\xc0\x80"[..],
        &b"\xed\xa0\x80"[..],
        &b"\xf4\x90\x80\x80"[..],
        &b"\xe0\xa0"[..],
    ] {
        assert_eq!(
            collect_child_args(&[Some(b"valid"), Some(b""), Some(bad), Some(&[0xff])]),
            Err(CollectError::InvalidUtf8 { argument_index: 2 })
        );
    }
}

#[test]
fn stop_does_not_inspect_invalid_suffix() {
    assert_eq!(
        collect_child_args(&[Some(b"one"), None, Some(&[0xff]), Some(b"two")]).unwrap(),
        ["one"]
    );
}

#[test]
fn ownership_survives_input_mutation_and_drop() {
    let values = {
        let mut source = b"owned\0bytes".to_vec();
        let values = collect_child_args(&[Some(&source)]).unwrap();
        source.fill(0xff);
        values
    };
    assert_eq!(values[0].as_bytes(), b"owned\0bytes");
}

#[test]
fn order_duplicates_inputs_and_many_empty_values_are_preserved() {
    let a = b"b".to_vec();
    let b = b"a".to_vec();
    let before = (a.clone(), b.clone());
    let values = collect_child_args(&[Some(&a), Some(&b), Some(&a)]).unwrap();
    assert_eq!(values, ["b", "a", "b"]);
    assert_eq!((a, b), before);
    assert_eq!(collect_child_args(&[Some(&b""[..]); 7]).unwrap(), [""; 7]);
}
