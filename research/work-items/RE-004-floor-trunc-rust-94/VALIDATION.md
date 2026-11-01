# Validation status

Source base: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.
Local native host: macOS arm64, Python 3.14.3, rustc 1.94.1.

- `make doctor verify catalogue-check reproduce`: exit 0 on this worktree.
  GNU binutils selected in PATH; LLVM_OBJDUMP=/usr/bin/objdump.
  All artifact digests/signatures, 38 imports and pinned submodules verified.
- `verify_static.py`: exit 0, including seven corrupted target structures.
- `verify_rust.py` ordinary Python: exit 0.
- Final `python3 -O -B verify_rust.py`: exit 0 after lossless stream archive
  packaging was added; same native numerical outcomes and mismatch counts.
- Both opt0/opt3: 66,132 rows, zero mismatches, two unit tests each.
  Repeat libraries, linked clients and complete output streams are raw equal.
- Six actually compiled mutants fail the frozen expectation comparison.
- All retained archive members match their raw lengths and SHA-256 records.

A single repository-wide `make test` sweep runs in the coordinating checkout
on this exact baseline plus the additive ceil Rust packet (#1382). It has
971 test files and remains pending at preparation time. This packet adds no
root tooling/test changes; its explicit native/static commands above were
run separately. Do not interpret that running shared sweep as a full-suite
pass in this worktree. Hosted CI and container builds have not been observed.
