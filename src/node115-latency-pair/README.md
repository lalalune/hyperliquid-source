# Node115 signed-pair numeric projections

Independent no_std Rust for the two post-provider numeric islands, bound to
node115 SHA256a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Inputs are raw signed components, not a recovered clock type/unit API.
uncapped_pair gives the first lane's value; capped_pair gives the second lane's
capped observer value and pre-call uncapped saved slot. Later record use requires
that slot to survive the opaque observer; no persistence or original ABI claim.

Build directly using actual pinned rustc1.94.1, edition2021, no Cargo graph:

    rustc --edition=2021 --crate-name node115_latency_pair --crate-type rlib lib.rs
    rustc --edition=2021 --test lib.rs -o /new/smoke

From repository root, tools/node115_latency_pair_rust.py --rustc /pinned/rustc
--output /new/output compares real opt0/opt3 clients, smoke, four compiled
mutants and own-archive repeat with frozen actual-instruction outcomes.
Exact commands, width blocker, source/target hashes and limits are retained in
research/work-items/RE-014-node115-latency-pair-rust.
