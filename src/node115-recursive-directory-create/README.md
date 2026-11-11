# Node115 recursive directory creation

This safe Unix Rust API implements the normal create/search/replay behavior
bound to [RE-012](../../research/work-items/RE-012-recursive-directory-create-115/README.md)
and node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Option byte zero makes one `mkdir` attempt. A nonzero byte searches upward on
`ENOENT`, then retries missing paths from parent to child; `EEXIST` is accepted
only when metadata says the path is a directory. Other errors are preserved.

The function uses real temporary directories in tests. It passes the requested
mode to the OS, so actual permissions remain subject to umask. This Rust API
does not reproduce the captured custom error/result ABI, C-string helper,
allocator behavior or arbitrary unwind effects. It makes no claim about
atomicity, race freedom, symlink safety or whole-node equivalence.

Run with Rust 1.95.0 or newer:

```sh
cargo test --offline --locked --manifest-path src/node115-recursive-directory-create/Cargo.toml
```
