//! Bounded node #115 directory-creation policy, expressed as a safe Rust API.
#![forbid(unsafe_code)]

use std::fs::{self, DirBuilder};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::DirBuilderExt;
use std::path::Path;

// These Linux errno values select the two special branches established by
// the node #115 errno-kind table: ENOENT climbs/replays and EEXIST checks stat.
const ERRNO_ENOENT: i32 = 2;
const ERRNO_EEXIST: i32 = 17;

/// Creates one directory, or walks upward and creates missing parents first.
///
/// A zero `recursive` byte makes exactly one attempt. Any nonzero byte enables
/// the observed parent-search and reverse-replay policy. Directory mode is
/// passed to the OS and remains subject to the process umask.
///
/// This is not the captured function's custom error/result ABI or path
/// conversion machinery. It implements its observed normal filesystem policy
/// using the host's Unix filesystem interface.
pub fn create_directory(path: &[u8], mode: u32, recursive: u8) -> io::Result<()> {
    if path.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "file name contained an unexpected NUL byte",
        ));
    }

    let path = Path::new(std::ffi::OsStr::from_bytes(path));
    if recursive == 0 {
        return create_one(path, mode);
    }

    if path.as_os_str().is_empty() || path.as_os_str().as_bytes().iter().all(|byte| *byte == b'/') {
        return Ok(());
    }

    let mut missing = Vec::new();
    let mut current = path.as_os_str().as_bytes().to_vec();

    loop {
        match create_one(Path::new(std::ffi::OsStr::from_bytes(&current)), mode) {
            Ok(()) => break,
            Err(error) if error.raw_os_error() == Some(ERRNO_ENOENT) => {
                missing.push(current.to_vec());
                match parent_path(&current) {
                    Some(parent) => current = parent,
                    None => break,
                }
            }
            Err(error) if error.raw_os_error() == Some(ERRNO_EEXIST) && is_directory(&current) => {
                break
            }
            Err(error) => return Err(error),
        }
    }

    while let Some(candidate) = missing.pop() {
        match create_one(Path::new(std::ffi::OsStr::from_bytes(&candidate)), mode) {
            Ok(()) => {}
            Err(error)
                if error.raw_os_error() == Some(ERRNO_EEXIST) && is_directory(&candidate) => {}
            Err(error) => return Err(error),
        }
    }

    Ok(())
}

fn create_one(path: &Path, mode: u32) -> io::Result<()> {
    let mut builder = DirBuilder::new();
    builder.mode(mode);
    builder.create(path)
}

fn is_directory(path: &[u8]) -> bool {
    fs::metadata(Path::new(std::ffi::OsStr::from_bytes(path)))
        .map(|metadata| metadata.is_dir())
        .unwrap_or(false)
}

fn parent_path(path: &[u8]) -> Option<Vec<u8>> {
    let mut end = path.len();
    while end > 0 && path[end - 1] == b'/' {
        end -= 1;
    }
    let slash = path[..end].iter().rposition(|byte| *byte == b'/')?;
    if slash == 0 {
        Some(vec![b'/'])
    } else {
        Some(path[..slash].to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::create_directory;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "node115-recursive-create-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).expect("create isolated test directory");
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn bytes(path: &std::path::Path) -> &[u8] {
        use std::os::unix::ffi::OsStrExt;
        path.as_os_str().as_bytes()
    }

    #[test]
    fn recursive_mode_creates_missing_parents_and_leaf() {
        let root = TempDir::new();
        let leaf = root.0.join("parent/child/leaf");

        create_directory(bytes(&leaf), 0o700, 1).unwrap();

        assert!(leaf.is_dir());
        assert!(root.0.join("parent/child").is_dir());
        assert!(root.0.join("parent").is_dir());
    }

    #[test]
    fn every_nonzero_option_byte_enables_parent_creation() {
        let root = TempDir::new();
        let leaf = root.0.join("parent/leaf");

        create_directory(bytes(&leaf), 0o700, 255).unwrap();

        assert!(leaf.is_dir());
        assert!(root.0.join("parent").is_dir());
    }

    #[test]
    fn zero_mode_makes_only_one_attempt() {
        let root = TempDir::new();
        let leaf = root.0.join("parent/leaf");

        let error = create_directory(bytes(&leaf), 0o700, 0).unwrap_err();

        assert_eq!(error.raw_os_error(), Some(2));
        assert!(!root.0.join("parent").exists());
    }

    #[test]
    fn existing_directory_is_accepted_only_in_recursive_mode() {
        let root = TempDir::new();
        let existing = root.0.join("existing");
        fs::create_dir(&existing).unwrap();

        create_directory(bytes(&existing), 0o700, 1).unwrap();
        assert_eq!(
            create_directory(bytes(&existing), 0o700, 0)
                .unwrap_err()
                .raw_os_error(),
            Some(17)
        );
    }

    #[test]
    fn existing_non_directory_preserves_already_exists_error() {
        let root = TempDir::new();
        let file = root.0.join("regular-file");
        fs::write(&file, b"x").unwrap();

        let error = create_directory(bytes(&file), 0o700, 1).unwrap_err();

        assert_eq!(error.raw_os_error(), Some(17));
    }

    #[test]
    fn errors_other_than_not_found_do_not_trigger_parent_creation() {
        let root = TempDir::new();
        let file = root.0.join("regular-file");
        fs::write(&file, b"x").unwrap();
        let child = file.join("child");

        let error = create_directory(bytes(&child), 0o700, 1).unwrap_err();

        assert_eq!(error.raw_os_error(), Some(20));
        assert!(file.is_file());
    }

    #[test]
    fn empty_and_root_paths_follow_recursive_early_return() {
        create_directory(b"", 0o700, 1).unwrap();
        create_directory(b"////", 0o700, 1).unwrap();
        assert_eq!(
            create_directory(b"", 0o700, 0).unwrap_err().raw_os_error(),
            Some(2)
        );
    }

    #[test]
    fn nul_is_rejected_before_filesystem_access() {
        assert_eq!(
            create_directory(b"bad\0path", 0o700, 1).unwrap_err().kind(),
            std::io::ErrorKind::InvalidInput
        );
    }
}
