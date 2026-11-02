# Node94 restart token projection

Independently authored Rust for the established ASCII token pipeline after
the restart caller's replacement helper returns: split on bytes 9–13 and 32,
discard empty and exact `--backup-logs` tokens, join the rest with one space.
Quotes and NUL remain literal bytes. Non-ASCII input gets a new explicit `None`
refusal; no original Unicode behavior is claimed.

Build directly with rustc 1.94.1, edition 2021; no external crates or Cargo
workspace are invented. `alloc` supplies this new API's output vector. This
does not reproduce the original allocator, ownership or failure behavior.

See `research/work-items/RE-001-restart-token-rust-94/` for authenticated
node94 evidence, frozen comparison inputs, independent harness and commands.
This does not parse shell syntax, perform the upstream replacement, spawn a
process or establish whole-function/ELF equivalence.
