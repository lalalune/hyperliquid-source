# Node115 snapshot selector prefixes

Independent no_std Rust for the selected worker/wrapper/mode/exit guard family
bound to node115 SHA256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
These enums are this component's branch labels, not the original ABI.
OtherUnclosedRoute does not assert a call or failure to return.

Build directly using pinned rustc1.94.1; no Cargo graph is claimed:

    rustc --edition=2021 --crate-name node115_snapshot_selectors --crate-type rlib lib.rs
    rustc --edition=2021 --test lib.rs -o /new/smoke

From repository root, run tools/node115_snapshot_selectors_rust.py with
--rustc /actual/pinned/rustc --output /new/output for real opt0/opt3 comparisons,
compiled smoke, six compiled mutants and raw own-archive reproducibility.
See research/work-items/RE-014-node115-snapshot-selectors-rust for exact scope,
commands, frozen native expectations, identities, results and remaining gaps.
