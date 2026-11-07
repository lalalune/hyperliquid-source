# Node #115 startup path admission

This dependency-free Rust adapter implements the path-admission relation used
by two startup enumerator wrappers. It is partial progress on
[issue #3927](https://github.com/lalalune/hyperliquid-source/issues/3927).
The issue's component gates remain false.

The caller supplies already-joined path bytes, per-entry enumeration outcomes,
metadata outcomes, and an opaque already-translated directory-open failure.
`admit_listing(View::Directories, ...)` retains the mapper's directory flag;
`View::NonDirectories` retains its false flag. Metadata failure produces false,
so the nested view can admit a path whose metadata failed if the text is valid.
It is not a regular-file predicate. Per-entry enumeration errors and invalid
UTF-8 suppress a path in both views.

The returned `Vec<String>` owns its path bytes and preserves input order and
duplicates. This is a source-owned **pre-sort admission view**. Native sorting,
container construction, duplicate handling, selecting the final directory,
`.lz4` suffix policy, checkpoint loading, and persistence remain outside this
API. No directory is opened, no metadata is read, and no captured target code
is executed or emulated.

The new binding is the first startup call through `0x64e0968` to `0x1501290`,
then `0x15b58c0` to directory-filter producer `0x153f470`, contrasted with the
nested call through `0x64e09d0` to `0x15021d0`, then `0x15b59e0` to
non-directory producer `0x1540a40`. These share the already mapped collector
and mapper. The input and error abstractions are intentionally not native
memory layouts; arbitrary malformed native records are not supported.

See the [digest-bound static evidence](../../research/work-items/RE-012-node115-startup-directory-admission/README.md)
for the exact caller, wrapper, mapper, filter and UTF-8 observations, prior
credit, and limitations. Static instruction checks are not a native runtime
differential test.

## Validation

Using the pinned Rust toolchain (rustc/cargo 1.95.0):

```sh
cargo test --offline --manifest-path src/node115-startup-admission/Cargo.toml
cargo test --offline --release --manifest-path src/node115-startup-admission/Cargo.toml
cargo fmt --manifest-path src/node115-startup-admission/Cargo.toml --check
```

Eight integration tests pass in each profile. They distinguish open failure
from an empty listing; directory/non-directory/metadata-failure populations;
five invalid UTF-8 forms across metadata outcomes; valid Unicode and empty
paths without an invented filename policy; 80 file-type/mode combinations;
supplied order and duplicates; and ownership of emitted bytes. The initial author run used installed Rust 1.93.1; an independent review
repeated the same tests and Clippy on the pinned Rust 1.95.0.
