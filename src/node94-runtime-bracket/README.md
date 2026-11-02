# node94-runtime-bracket

Four maintained node94 wrapper records establish a selected runtime state-cell bracket but no independent Rust implementation. This adds its conditional decision protocol: prior byte 2 fails before body entry; otherwise the body state is 2; missing context and non-2 post-state fail without restoring; a valid post-state restores the prior byte. The saved flag word and cleared low byte are projected separately.

Build directly with rustc 1.94.1, edition 2021. Safe `no_std`, no external dependencies or root Cargo workspace. The evidence packet `research/work-items/RE-001-runtime-bracket-rust-94/` retains the complete commands, target identity and comparison scope.

This is a pure projection conditional on reaching the selected bracket and normal body return, not a TLS implementation. Entry bypasses, initialization/destruction, actual body/scheduler/park effects, full flag restoration, native enum validity, panic behavior, unwinding and concurrency remain unproved. Body_state describes a selected store and does not execute a body.
