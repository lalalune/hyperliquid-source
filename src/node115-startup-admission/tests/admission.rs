use node115_startup_admission::{admit_listing, Entry, Metadata, View};

fn path(bytes: &[u8], metadata: Metadata) -> Entry<'_> {
    Entry::Path {
        joined_path_bytes: bytes,
        metadata,
    }
}

fn admitted(view: View, entries: &[Entry<'_>]) -> Vec<String> {
    admit_listing::<()>(view, Ok(entries)).unwrap()
}

#[test]
fn directory_open_failure_stays_distinct_from_an_empty_listing() {
    #[derive(Debug, PartialEq)]
    struct OpaqueFailure(u64);
    for view in [View::Directories, View::NonDirectories] {
        assert_eq!(
            admit_listing(view, Err(OpaqueFailure(17))),
            Err(OpaqueFailure(17))
        );
        assert_eq!(admitted(view, &[]), Vec::<String>::new());
    }
}

#[test]
fn the_two_wrappers_admit_different_populations() {
    let entries = [
        path(b"root/100", Metadata::Mode(0x41ed)),
        path(b"root/regular", Metadata::Mode(0x81a4)),
        path(b"root/link", Metadata::Mode(0xa1ff)),
        path(b"root/socket", Metadata::Mode(0xc1ed)),
        path(b"root/unknown", Metadata::Failed),
        Entry::Failed,
    ];
    assert_eq!(admitted(View::Directories, &entries), ["root/100"]);
    assert_eq!(
        admitted(View::NonDirectories, &entries),
        ["root/regular", "root/link", "root/socket", "root/unknown"]
    );
}

#[test]
fn metadata_failure_is_admitted_by_the_nested_view_when_text_is_valid() {
    let entries = [path(b"root/vanished", Metadata::Failed)];
    assert!(admitted(View::Directories, &entries).is_empty());
    assert_eq!(admitted(View::NonDirectories, &entries), ["root/vanished"]);
}

#[test]
fn text_failure_suppresses_both_metadata_outcomes() {
    let bad: &[&[u8]] = &[
        b"root/\xff",
        b"root/\xc0\x80",
        b"root/\xed\xa0\x80",
        b"root/\xf4\x90\x80\x80",
        b"root/\xe2\x82",
    ];
    for bytes in bad {
        for metadata in [
            Metadata::Failed,
            Metadata::Mode(0x4000),
            Metadata::Mode(0x8000),
        ] {
            for view in [View::Directories, View::NonDirectories] {
                assert!(admitted(view, &[path(bytes, metadata)]).is_empty());
            }
        }
    }
}

#[test]
fn valid_unicode_and_empty_paths_have_no_invented_filename_policy() {
    let names = ["root/é", "root/中", "root/🦀", ""];
    let entries: Vec<_> = names
        .iter()
        .map(|s| path(s.as_bytes(), Metadata::Mode(0x4000)))
        .collect();
    assert_eq!(admitted(View::Directories, &entries), names);
}

#[test]
fn mode_flags_outside_the_type_mask_do_not_change_admission() {
    for kind in 0..16u32 {
        for extras in [0, 1, 0xfff, 0x1234_0000, 0xffff_0fff] {
            let entry = path(b"root/entry", Metadata::Mode((kind << 12) | extras));
            assert_eq!(
                admitted(View::Directories, &[entry]).len(),
                usize::from(kind == 4)
            );
            assert_eq!(
                admitted(View::NonDirectories, &[entry]).len(),
                usize::from(kind != 4)
            );
        }
    }
}

#[test]
fn admission_preserves_supplied_order_and_duplicates_before_native_sorting() {
    let entries = [
        path(b"z", Metadata::Mode(0x4000)),
        path(b"a", Metadata::Mode(0x4000)),
        path(b"z", Metadata::Mode(0x4000)),
    ];
    assert_eq!(admitted(View::Directories, &entries), ["z", "a", "z"]);
}

#[test]
fn emitted_paths_are_owned_independently_of_supplied_bytes() {
    let mut bytes = b"root/entry".to_vec();
    let result = admitted(View::Directories, &[path(&bytes, Metadata::Mode(0x4000))]);
    bytes.fill(b'x');
    assert_eq!(result, ["root/entry"]);
}
