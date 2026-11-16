use node115_startup_admission::{Metadata, View};
use node115_startup_path_join::{NameEntry, admit_named_listing, join_path_bytes};

#[test]
fn exact_path_push_bytes_without_normalization() {
    for (base, child, expected) in [
        (&b""[..], &b""[..], &b""[..]),
        (b"", b"relative", b"relative"),
        (b"root", b"", b"root/"),
        (b"root/", b"", b"root/"),
        (b"root", b"one", b"root/one"),
        (b"root/", b"one", b"root/one"),
        (b"root//", b".././x", b"root//.././x"),
        (b"root", b"/absolute//x", b"/absolute//x"),
        (b"root", b"back\\slash", b"root/back\\slash"),
    ] {
        assert_eq!(join_path_bytes(base, child), expected);
    }
}

#[test]
fn metadata_sees_joined_bytes_before_utf8_filter_and_nul_is_excluded() {
    let names = [
        NameEntry::Name(c"relative"),
        NameEntry::Failed,
        NameEntry::Name(c"/valid"),
        NameEntry::Name(c"\xff"),
    ];
    let mut calls = Vec::new();
    let result =
        admit_named_listing::<(), _>(View::Directories, b"bad\xff", Ok(&names), &mut |bytes| {
            calls.push(bytes.to_vec());
            Metadata::Mode(0x4000)
        })
        .unwrap();
    assert_eq!(
        calls,
        [
            b"bad\xff/relative".to_vec(),
            b"/valid".to_vec(),
            b"bad\xff/\xff".to_vec()
        ]
    );
    assert_eq!(result, ["/valid"]);
}

#[test]
fn error_and_failed_entry_skip_metadata_and_nested_view_uses_result() {
    let mut calls = Vec::new();
    let result = admit_named_listing(
        View::Directories,
        b"x",
        Err::<&[NameEntry<'_>], _>(17),
        &mut |bytes| {
            calls.push(bytes.to_vec());
            Metadata::Failed
        },
    );
    assert_eq!(result, Err(17));
    assert!(calls.is_empty());
    let names = [
        NameEntry::Failed,
        NameEntry::Name(c"b"),
        NameEntry::Name(c"a"),
    ];
    let result =
        admit_named_listing::<(), _>(View::NonDirectories, b"root/", Ok(&names), &mut |bytes| {
            calls.push(bytes.to_vec());
            Metadata::Failed
        })
        .unwrap();
    assert_eq!(calls, [b"root/b".to_vec(), b"root/a".to_vec()]);
    assert_eq!(result, ["root/b", "root/a"]);
}
