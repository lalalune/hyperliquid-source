#![forbid(unsafe_code)]

//! Concrete node #115 overwrite/write/close lifecycle, exposed as a safe API.
//!
//! The original Rust function type and ABI are not recovered. The path and
//! payload are accepted as slices so their bounds are explicit.

use std::fs::OpenOptions;
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;

/// Opens or creates `path`, truncates it, writes `data`, and closes it.
///
/// The observed target uses write/create/truncate, mode `0666` subject to the
/// process umask, and close-on-exec. Empty data still opens and truncates the
/// file. A close error is not surfaced, matching the observed ignored close
/// return. This is not the captured function's custom error/result ABI.
pub fn write_file(path: &[u8], data: &[u8]) -> io::Result<()> {
    if path.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "file name contained an unexpected NUL byte",
        ));
    }

    let path = std::ffi::OsStr::from_bytes(path);
    let mut options = OpenOptions::new();
    options.write(true).truncate(true).create(true).mode(0o666);
    #[cfg(target_os = "linux")]
    options.custom_flags(0x80000); // O_CLOEXEC on Linux.

    let mut file = loop {
        match options.open(path) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => break result?,
        }
    };

    write_observed_loop(&mut file, data)?;
    drop(file); // File::drop closes; the target ignores close's return value.
    Ok(())
}

fn write_observed_loop(writer: &mut impl Write, data: &[u8]) -> io::Result<()> {
    let mut remaining = data;
    while !remaining.is_empty() {
        match writer.write(remaining) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "write returned zero with bytes remaining",
                ));
            }
            Ok(count) if count <= remaining.len() => remaining = &remaining[count..],
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "writer reported more bytes than requested",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{write_file, write_observed_loop};
    use std::collections::VecDeque;
    use std::fs;
    use std::io::{self, Write};
    use std::os::unix::ffi::OsStrExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "node115-file-write-{}-{}",
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

    #[test]
    fn overwrites_existing_file_before_return() {
        let directory = TempDir::new();
        let path = directory.0.join("output.bin");
        fs::write(&path, b"old content longer than replacement").unwrap();

        write_file(path.as_os_str().as_bytes(), b"new").unwrap();

        assert_eq!(fs::read(&path).unwrap(), b"new");
    }

    #[test]
    fn empty_payload_still_creates_and_truncates() {
        let directory = TempDir::new();
        let path = directory.0.join("empty.bin");
        fs::write(&path, b"old content").unwrap();

        write_file(path.as_os_str().as_bytes(), b"").unwrap();

        assert_eq!(fs::read(&path).unwrap(), b"");
    }

    #[test]
    fn interior_nul_is_rejected_before_open() {
        let error = write_file(b"bad\0path", b"data").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn open_failure_is_returned() {
        let directory = TempDir::new();
        let error = write_file(directory.0.as_os_str().as_bytes(), b"data").unwrap_err();
        assert!(error.raw_os_error().is_some());
    }

    #[derive(Default)]
    struct ScriptedWriter {
        steps: VecDeque<Step>,
        bytes: Vec<u8>,
    }

    enum Step {
        Count(usize),
        Interrupted,
        Zero,
    }

    impl Write for ScriptedWriter {
        fn write(&mut self, input: &[u8]) -> io::Result<usize> {
            match self.steps.pop_front().expect("scripted write step") {
                Step::Count(count) => {
                    self.bytes.extend_from_slice(&input[..count]);
                    Ok(count)
                }
                Step::Interrupted => Err(io::Error::from(io::ErrorKind::Interrupted)),
                Step::Zero => Ok(0),
            }
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn partial_writes_and_interrupts_advance_only_on_progress() {
        let mut writer = ScriptedWriter {
            steps: [
                Step::Count(2),
                Step::Interrupted,
                Step::Count(1),
                Step::Count(3),
            ]
            .into(),
            ..ScriptedWriter::default()
        };

        write_observed_loop(&mut writer, b"abcdef").unwrap();

        assert_eq!(writer.bytes, b"abcdef");
        assert!(writer.steps.is_empty());
    }

    #[test]
    fn zero_write_with_remaining_data_returns_write_zero() {
        let mut writer = ScriptedWriter {
            steps: [Step::Zero].into(),
            ..ScriptedWriter::default()
        };

        assert_eq!(
            write_observed_loop(&mut writer, b"nonempty")
                .unwrap_err()
                .kind(),
            io::ErrorKind::WriteZero
        );
    }
}
