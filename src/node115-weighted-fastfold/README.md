# Node115 two-span checked weight fold

Independent no_std Rust for the closed fast suffix, bound to node115 SHA256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
weighted_gate takes an explicit first-provider status/basis and two safe weight
slices. It checks u64 addition then strict128-bit2*S<3*B. The source does not
implement the first provider, generic iterator, original ABI or consensus policy.

Build directly with actual pinned rustc1.94.1, edition2021 (no Cargo graph):

    rustc --edition=2021 --crate-name node115_weighted_fastfold --crate-type rlib lib.rs
    rustc --edition=2021 --test lib.rs -o /new/smoke

From repository root, tools/node115_weighted_fold_rust.py --rustc /pinned/rustc
--output /new/output performs real two-profile comparisons, compiled smoke,
three compiled mutants and raw own-archive repeat. Exact commands, target/source
hashes, pre-Rust frozen corpus, development failures and limits are retained in
research/work-items/RE-014-node115-weighted-fastfold-rust.
