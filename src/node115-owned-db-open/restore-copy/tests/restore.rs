use node115_restore_copy::prepare_first_copy;
use std::{
    ffi::OsStr,
    fs, io,
    os::unix::fs::MetadataExt,
    path::PathBuf,
    process,
    sync::atomic::{AtomicUsize, Ordering},
};

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> io::Result<Self> {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        loop {
            let dir = std::env::temp_dir().join(format!(
                "node115-restore-{}-{}",
                process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::create_dir(&dir) {
                Ok(()) => return Ok(Self(dir)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn selected_directory_is_source_and_live_home_is_destination() -> io::Result<()> {
    let scratch = Scratch::new()?;
    let selected = scratch.0.join("old checkpoints/37");
    let live = scratch.0.join("new live home/db");
    let nested = selected.join("EvmState/part");
    fs::create_dir_all(&nested)?;
    fs::write(nested.join("data"), b"fixture payload")?;
    fs::write(selected.join("lt_hashes.json"), b"separate later input")?;
    let mut command = prepare_first_copy(&selected, &live)?;
    assert!(live.is_dir());
    assert_eq!(command.get_program(), "cp");
    let expected = selected.join("EvmState");
    assert_eq!(
        command.get_args().collect::<Vec<_>>(),
        [OsStr::new("-al"), expected.as_os_str(), live.as_os_str()]
    );
    let result = command.output()?;
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let original = fs::metadata(nested.join("data"))?;
    let restored = live.join("EvmState/part/data");
    assert_eq!(fs::read(&restored)?, b"fixture payload");
    let copy = fs::metadata(restored)?;
    assert_eq!((copy.dev(), copy.ino()), (original.dev(), original.ino()));
    assert!(!live.join("lt_hashes.json").exists());
    Ok(())
}

#[test]
fn missing_subtree_and_unusable_home_fail_at_different_points() -> io::Result<()> {
    let scratch = Scratch::new()?;
    let selected = scratch.0.join("37");
    fs::create_dir(&selected)?;
    fs::write(selected.join("CHECKPOINT_COMPLETE"), b"")?;
    let live = scratch.0.join("db");
    let error = prepare_first_copy(&selected, &live).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::NotADirectory);
    assert!(live.is_dir());
    assert!(!live.join("EvmState").exists());

    fs::write(selected.join("EvmState"), b"regular file")?;
    assert_eq!(
        prepare_first_copy(&selected, &live).unwrap_err().kind(),
        io::ErrorKind::NotADirectory
    );

    let file = scratch.0.join("file-as-home");
    fs::write(&file, b"untouched")?;
    assert!(prepare_first_copy(&selected, &file).is_err());
    assert_eq!(fs::read(file)?, b"untouched");
    Ok(())
}

#[test]
fn formatted_source_preserves_the_separator() -> io::Result<()> {
    let scratch = Scratch::new()?;
    let selected = scratch.0.join("old/37/");
    fs::create_dir_all(selected.join("EvmState"))?;
    let command = prepare_first_copy(&selected, &scratch.0)?;
    let mut expected = selected.as_os_str().to_owned();
    expected.push("/EvmState");
    assert!(expected.to_str().unwrap().ends_with("37//EvmState"));
    assert_eq!(command.get_args().nth(1), Some(expected.as_os_str()));
    Ok(())
}
