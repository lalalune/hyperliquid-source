# Node94 gossip-reload selected gates

Independent no_std Rust for the raw mixed-signed metadata comparison and IEEE
throttle predicate. No clock, filesystem, parser or reload operation is run.
See ../../research/work-items/RE-001-gossip-reload-rust-94/README.md for the exact
target, assumptions, compiled comparisons, finite corpus and limitations.
Compile lib.rs directly with pinned rustc1.94.1; the input-only client links its
rlib. No root Cargo graph is invented.
