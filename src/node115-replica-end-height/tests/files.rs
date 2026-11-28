use node115_replica_end_height::{
    Error, StartingHeightCheck, check_starting_height, directory_end_height, latest_end_height,
};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicUsize, Ordering},
};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static SEQ: AtomicUsize = AtomicUsize::new(0);
        loop {
            let dir = std::env::temp_dir().join(format!(
                "replica-height-{}-{}",
                std::process::id(),
                SEQ.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::create_dir(&dir) {
                Ok(()) => return Self(dir),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => panic!("{e}"),
            }
        }
    }
    fn write(&self, name: &str, data: &[u8]) {
        let path = self.0.join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, data).unwrap();
    }
    fn root(&self) -> &Path {
        &self.0
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn takes_latest_date_and_latest_non_lz4_path_by_bytes() {
    let f = Fixture::new();
    f.write("x/date10/9999", b"\n");
    f.write("x/date9/100", b"\n\n\n");
    f.write("x/date9/9", b"\0\n\xff\nunterminated");
    f.write("x/date9/zz.lz4", b"ignored");
    assert_eq!(directory_end_height(&f.root().join("x")).unwrap(), 11);
    f.write("x/date9/zzz.LZ4", b"");
    assert!(matches!(
        directory_end_height(&f.root().join("x")),
        Err(Error::Filename(_))
    ));
}

#[test]
fn failed_candidates_use_up_slots_in_the_five_directory_window() {
    let f = Fixture::new();
    for (name, data) in [
        ("00/d/8000", ""),
        ("01/d/7000", ""),
        ("02/d/21", "\n\n"),
        ("03/d/30", "\n"),
        ("04/d/invalid", ""),
        ("05/d/6", "\n"),
        ("06/d/z.lz4", ""),
    ] {
        f.write(name, data.as_bytes());
    }
    assert_eq!(latest_end_height(f.root()).unwrap(), 31);
    f.write("07/d/7", b"");
    f.write("08/d/8", b"");
    assert_eq!(latest_end_height(f.root()).unwrap(), 8);
}

#[test]
fn file_scanning_and_saturation() {
    let f = Fixture::new();
    f.write("one/date/+42", &[b'\n'; 9001]);
    assert_eq!(directory_end_height(&f.root().join("one")).unwrap(), 9043);
    f.write("two/date/18446744073709551615", b"\n");
    assert_eq!(
        directory_end_height(&f.root().join("two")).unwrap(),
        u64::MAX
    );
    f.write("three/date/18446744073709551616", b"");
    assert!(matches!(
        directory_end_height(&f.root().join("three")),
        Err(Error::Filename(_))
    ));
}

#[test]
fn empty_directories_and_errors_stay_distinct() {
    let f = Fixture::new();
    assert!(matches!(
        latest_end_height(f.root()),
        Err(Error::NoEndHeights)
    ));
    assert!(matches!(
        directory_end_height(f.root()),
        Err(Error::NoDateDirectory)
    ));
    assert!(matches!(
        latest_end_height(&f.root().join("missing")),
        Err(Error::Io(_))
    ));
    fs::create_dir(f.root().join("date")).unwrap();
    assert!(matches!(
        directory_end_height(f.root()),
        Err(Error::NoUncompressedFile)
    ));
    f.write("date/+0", b"abc");
    assert_eq!(directory_end_height(f.root()).unwrap(), 0);
}

#[test]
fn startup_compares_the_observed_end_including_equality() {
    let f = Fixture::new();
    f.write("0000/20261024/400", b"line\n");
    f.write("0001/20261025/500", b"line\npartial");
    assert!(matches!(
        check_starting_height(f.root(), 500, 1),
        StartingHeightCheck::BelowReplicaEnd { last_applied: 501 }
    ));
    for starting in [501, 502] {
        assert!(matches!(
            check_starting_height(f.root(), starting, 1),
            StartingHeightCheck::AtOrAboveReplicaEnd { last_applied: 501 }
        ));
    }
}

#[test]
fn startup_distinguishes_unavailable_end_from_disabled_mode() {
    let f = Fixture::new();
    assert!(matches!(
        check_starting_height(f.root(), 0, 1),
        StartingHeightCheck::ReplicaEndUnavailable(Error::NoEndHeights)
    ));
    let missing = f.root().join("unavailable");
    assert!(matches!(
        check_starting_height(&missing, 0, 1),
        StartingHeightCheck::ReplicaEndUnavailable(Error::Io(_))
    ));
    for mode in [0, 2, u8::MAX] {
        assert!(matches!(
            check_starting_height(&missing, 0, mode),
            StartingHeightCheck::Disabled
        ));
    }
}

#[test]
fn startup_compares_end_height_as_unsigned() {
    let f = Fixture::new();
    f.write("0000/20261025/18446744073709551615", b"line\n");
    assert!(matches!(
        check_starting_height(f.root(), i64::MAX as u64, 1),
        StartingHeightCheck::BelowReplicaEnd {
            last_applied: u64::MAX
        }
    ));
    assert!(matches!(
        check_starting_height(f.root(), u64::MAX, 1),
        StartingHeightCheck::AtOrAboveReplicaEnd {
            last_applied: u64::MAX
        }
    ));
}
