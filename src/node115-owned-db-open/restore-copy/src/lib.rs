#![forbid(unsafe_code)]
//! First copy prepared on the node #115 exact-height local restore path.

use std::{fs, io, path::Path, process::Command};

/// Prepare the live home and return the first command on the mode-1 path.
/// The caller supplies the selected historical directory and the already
/// resolved live DB home. Any earlier cleanup belongs to the caller.
/// Returning the command lets an offline caller inspect or run it.
pub fn prepare_first_copy(selected_directory: &Path, live_home: &Path) -> io::Result<Command> {
    if !live_home.is_dir() {
        fs::create_dir_all(live_home)?;
    }

    // The captured formatter appends a literal slash, including when the
    // displayed path already ends in one. Keep that byte in the argv.
    let mut source = selected_directory.as_os_str().to_os_string();
    source.push("/EvmState");
    if !Path::new(&source).is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotADirectory,
            "checkpoint EvmState directory unavailable",
        ));
    }
    let mut command = Command::new("cp");
    command.arg("-al").arg(source).arg(live_home);
    Ok(command)
}
