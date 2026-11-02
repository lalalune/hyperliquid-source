# Node94 raw cumulative-minute local relation

Independent no_std Rust bound to node94 SHA256
3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f.
classify_raw_word preserves the14selected copies' u32 division and guard order.
LocalMinute is an own branch label, not an original error enum or valid-time
constructor. Raw1440 admission is not a caller-reachability claim.

Build directly with actual pinned rustc1.94.1, edition2021, no Cargo graph:

    rustc --edition=2021 --crate-name node94_cumulative_minute --crate-type rlib lib.rs
    rustc --edition=2021 --test lib.rs -o /new/smoke

From repository root, tools/cumulative_minute_rust.py --rustc /pinned/rustc
--output /new/output compares real opt0/opt3 clients, compiled mutants/smoke
and own-archive repeat against the pre-Rust frozen native expectations.
Exact populations, target/source hashes, commands and limits are retained in
research/work-items/RE-001-cumulative-minute-rust-94.
