use node115_evm_archive_plan::plan_archive;
use std::cell::Cell;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

const DATE: &str = "20260120";
static NEXT: AtomicUsize = AtomicUsize::new(0);

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "hl-archive-plan-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        Self(root)
    }
    fn root(&self) -> &str {
        self.0.to_str().unwrap()
    }
    fn statuses(&self) -> PathBuf {
        self.0.join("data/periodic_abci_state_statuses").join(DATE)
    }
    fn set_statuses(&self, names: &[&str]) {
        fs::create_dir_all(self.statuses()).unwrap();
        for name in names {
            fs::write(self.statuses().join(name), []).unwrap();
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn literal_membership_and_two_distinct_archive_names() {
    let f = Fixture::new();
    f.set_statuses(&["0", "+1", "01", "7", "8 ", "１０", "18446744073709551615"]);
    fs::create_dir(f.statuses().join("6")).unwrap();
    fs::write(f.statuses().join("6/1"), []).unwrap();
    let root = format!("{}/", f.root());
    let result = plan_archive(&root, DATE, &[0, 1, 6, 7, 7, 8, 10, u64::MAX], || 19)
        .unwrap()
        .unwrap();
    assert_eq!(result.members, ["0", "7", "7", "18446744073709551615"]);
    assert_eq!(
        result.temporary_path,
        "/tmp/evm_state_checkpoints_0_18446744073709551615_19.tar"
    );
    assert_eq!(
        result.destination_path,
        format!("{root}/data/daily_evm_checkpoints/{DATE}/0_18446744073709551615.tar")
    );
    assert!(!f.0.join("data/daily_evm_checkpoints").exists());
}

#[test]
fn missing_status_root_is_an_error_but_empty_intersection_skips_id() {
    let f = Fixture::new();
    assert_eq!(
        plan_archive(f.root(), DATE, &[2], || panic!())
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::NotFound
    );
    f.set_statuses(&["02", "+2", "2.rmp"]);
    assert_eq!(
        plan_archive(f.root(), DATE, &[2], || panic!()).unwrap(),
        None
    );
    assert_eq!(
        plan_archive(f.root(), DATE, &[], || panic!()).unwrap(),
        None
    );
}

#[test]
fn id_is_obtained_before_testing_the_final_regular_file() {
    let f = Fixture::new();
    f.set_statuses(&["20"]);
    let dir = f.0.join("data/daily_evm_checkpoints").join(DATE);
    fs::create_dir_all(&dir).unwrap();
    let dest = dir.join("20_20.tar");
    fs::write(&dest, b"already archived").unwrap();
    let calls = Cell::new(0);
    let id = || {
        calls.set(calls.get() + 1);
        u64::MAX
    };
    assert_eq!(plan_archive(f.root(), DATE, &[20], id).unwrap(), None);
    assert_eq!(calls.get(), 1);
    assert_eq!(fs::read(&dest).unwrap(), b"already archived");
    fs::remove_file(&dest).unwrap();
    fs::create_dir(&dest).unwrap();
    let result = plan_archive(f.root(), DATE, &[20], id).unwrap().unwrap();
    assert_eq!(
        result.temporary_path,
        "/tmp/evm_state_checkpoints_20_20_18446744073709551615.tar"
    );
    assert_eq!(calls.get(), 2);
}

#[test]
fn metadata_failure_keeps_a_non_directory_name() {
    let f = Fixture::new();
    f.set_statuses(&[]);
    symlink("missing-target", f.statuses().join("11")).unwrap();
    let result = plan_archive(f.root(), DATE, &[11], || 0).unwrap().unwrap();
    assert_eq!(result.members, ["11"]);
}
