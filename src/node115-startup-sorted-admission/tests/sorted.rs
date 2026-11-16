use node115_startup_admission::{Entry, Metadata, View};
use node115_startup_sorted_admission::admit_sorted_listing;

fn path(bytes: &[u8], metadata: Metadata) -> Entry<'_> {
    Entry::Path {
        joined_path_bytes: bytes,
        metadata,
    }
}

#[test]
fn sorted_admission_covers_native_size_boundaries() {
    for count in [20, 21, 32, 33, 64, 65, 170, 171, 4097] {
        let names: Vec<String> = (0..count).rev().map(|n| format!("root/{n:05}")).collect();
        let entries: Vec<_> = names
            .iter()
            .map(|s| path(s.as_bytes(), Metadata::Mode(0x4000)))
            .collect();
        let result = admit_sorted_listing::<()>(View::Directories, Ok(&entries)).unwrap();
        let expected: Vec<String> = (0..count).map(|n| format!("root/{n:05}")).collect();
        assert_eq!(result, expected, "count {count}");
    }
}

#[test]
fn sorted_admission_preserves_duplicates_filters_and_open_error() {
    let entries = [
        path(b"root/2", Metadata::Mode(0x4000)),
        path(b"root/10", Metadata::Mode(0x4000)),
        path("root/é".as_bytes(), Metadata::Mode(0x4000)),
        path(b"root/1", Metadata::Mode(0x4000)),
        path(b"root/10", Metadata::Mode(0x4000)),
        path(b"root/ignored", Metadata::Mode(0x8000)),
        path(b"root/\xff", Metadata::Mode(0x4000)),
        Entry::Failed,
    ];
    assert_eq!(
        admit_sorted_listing::<()>(View::Directories, Ok(&entries)).unwrap(),
        ["root/1", "root/10", "root/10", "root/2", "root/é"]
    );
    assert_eq!(
        admit_sorted_listing(View::Directories, Err::<&[Entry<'_>], _>(17)),
        Err(17)
    );
}

#[test]
fn sorted_nested_view_includes_failed_metadata_and_excludes_directories() {
    let entries = [
        path(b"root/z", Metadata::Failed),
        path(b"root/a", Metadata::Mode(0x8000)),
        path(b"root/m", Metadata::Mode(0x4000)),
        path(b"root/a", Metadata::Failed),
    ];
    assert_eq!(
        admit_sorted_listing::<()>(View::NonDirectories, Ok(&entries)).unwrap(),
        ["root/a", "root/a", "root/z"]
    );
}
