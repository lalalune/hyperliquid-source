# node94-cold-admission

The maintained static packet identifies cold-state digest and helper-result branches but has no independent Rust implementation. This adds a safe fixed-size digest comparison and the selected admission route: mismatch first; nonzero optional word with zero input word next; exact helper word 0x8000000000000040 permits the fetched-prefix route. Branch outcomes are descriptions rather than diagnostic, helper or trap execution.

Build directly with rustc 1.94.1, edition 2021. Safe `no_std`, no external dependencies or root Cargo workspace. The evidence packet `research/work-items/RE-001-cold-admission-rust-94/` retains the complete commands, target identity and comparison scope.

Fetch/hash/clone/validation helper internals, cryptographic or constant-time guarantees, concrete state types and reachability, diagnostic/trap effects, ownership/unwind and original ABI remain unclosed. ReturnFetchedPrefix denotes a route only; this library does not construct or return that native 56-byte state prefix.
