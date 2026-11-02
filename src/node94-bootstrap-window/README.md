# Node94 selected bootstrap-window arithmetic

Standalone independently authored no_std Rust for the already established raw
unsigned current/target relation. No original ABI or network/async behavior.
The target identity, freeze, comparisons and limitations are documented in
../../research/work-items/RE-001-bootstrap-window-rust-94/README.md.
Compile lib.rs directly with pinned rustc1.94.1; the separately linked input-only
driver is an offline comparator client. No root Cargo workspace is introduced.
