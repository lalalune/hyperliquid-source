# Node94 selected snapshot admission

Independent no_std branch classifier for raw u32 tag and u64 height/freeze words.
All three captured lane prefixes share this predicate. It performs no snapshot,
filesystem, captured assertion or helper call. Evidence/builds/limits:
../../research/work-items/RE-001-snapshot-admission-rust-94/README.md.
Compile lib.rs directly with pinned rustc1.94.1; input_only_driver.rs links the
resulting rlib for offline comparisons. No root Cargo graph is fabricated.
