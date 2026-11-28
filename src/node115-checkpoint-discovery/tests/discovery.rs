use node115_checkpoint_discovery::{candidates, find_checkpoint};
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

struct Tree(PathBuf);
impl Tree {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "hl115-checkpoint-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn dir(&self, name: &str) -> PathBuf {
        let p = self.0.join(name);
        fs::create_dir(&p).unwrap();
        p
    }
}
impl Drop for Tree {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn marker(directory: &Path, marker: &str) {
    File::create(directory.join(marker)).unwrap();
}
const COMPLETE: &str = "CHECKPOINT_COMPLETE";
const EVM: &str = "CHECKPOINT_COMPLETE_EvmState";

#[test]
fn canonical_spelling_precedes_marker_admission_and_preserves_duplicates() {
    let tree = Tree::new();
    marker(&tree.dir("+0042"), COMPLETE);
    assert!(find_checkpoint(&tree.0, 42).is_none());
    let canonical = tree.dir("42");
    marker(&canonical, EVM);
    tree.dir("00042");
    let rows = candidates(&tree.0).unwrap();
    assert_eq!(rows.len(), 3);
    assert!(rows.iter().all(|r| r.height == 42 && r.path == canonical));
}

#[test]
fn selects_an_exact_numeric_height_and_requires_a_regular_marker() {
    let tree = Tree::new();
    for name in [
        "+",
        "18446744073709551616",
        "-1",
        "3x",
        "0",
        "9",
        "99",
        "100",
        "18446744073709551615",
    ] {
        marker(&tree.dir(name), COMPLETE);
    }
    let incomplete = tree.dir("98");
    fs::create_dir(incomplete.join(COMPLETE)).unwrap();
    marker(&incomplete, "CHECKPOINT_COMPLETE_evm");
    let alternate = tree.dir("10");
    fs::create_dir(alternate.join(COMPLETE)).unwrap();
    marker(&alternate, EVM);
    marker(&tree.dir("１"), COMPLETE);
    marker(&tree.0, "97");
    let rows = candidates(&tree.0).unwrap();
    assert_eq!(
        rows.iter().map(|r| r.height).collect::<Vec<_>>(),
        [u64::MAX, 100, 99, 10, 9, 0]
    );
    assert_eq!(find_checkpoint(&tree.0, 10).unwrap().path, alternate);
    assert!(find_checkpoint(&tree.0, 98).is_none());
    assert!(candidates(&tree.0.join("missing")).unwrap().is_empty());
    assert!(candidates(&tree.0.join("97")).unwrap().is_empty());
}

#[test]
fn visits_more_than_one_small_sort_window() {
    let tree = Tree::new();
    for h in 0..73 {
        let path = tree.dir(&(h * 29 % 73).to_string());
        marker(&path, COMPLETE);
    }
    let actual: Vec<_> = candidates(&tree.0)
        .unwrap()
        .into_iter()
        .map(|row| row.height)
        .collect();
    assert_eq!(actual, (0..73).rev().collect::<Vec<_>>());
}

#[test]
fn admits_the_node115_uppercase_evm_marker() {
    let tree = Tree::new();
    let directory = tree.dir("42");
    marker(&directory, "CHECKPOINT_COMPLETE_EVMSTATE");
    assert_eq!(find_checkpoint(&tree.0, 42).unwrap().path, directory);
}
