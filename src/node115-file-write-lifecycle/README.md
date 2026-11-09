# Node115 file write lifecycle

This dependency-free Rust component implements the concrete overwrite/write/
close path described by the [RE-012 static evidence packet](../../research/work-items/RE-012-file-write-lifecycle-115/README.md), bound to node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

`write_file` rejects an interior NUL, opens with write/create/truncate and mode
`0666`, retries interrupted opens, writes until complete while retrying
interrupted writes, reports a zero write as `WriteZero`, and drops the file
after success or write failure. On Linux the crate requests `O_CLOEXEC`.
Creating a file remains subject to the real process umask. Empty data still
opens/truncates and closes the file; close errors are ignored.

Tests use isolated temporary directories for actual create/truncate/write/close
behavior and a scripted writer only for partial/EINTR/zero progress branches.
They do not run or emulate the captured binary, claim the original custom
error/result ABI, reproduce the node's owned CString allocation side effects,
prove syscall identity or close-error behavior, or establish file durability,
atomic publication, permission outcomes, or whole-node equivalence.

Run `cargo test --offline --locked --manifest-path
src/node115-file-write-lifecycle/Cargo.toml` with Rust 1.95.0 or newer. On the
target Linux x86-64 ABI, build the library with the same manifest and
`--target x86_64-unknown-linux-gnu`.
