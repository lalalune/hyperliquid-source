# Node115 two-span checked weight fold

Independent no_std Rust for the closed fast suffix, bound to node115 SHA256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
weighted_gate takes an explicit first-provider status/basis and two safe weight
slices. It checks u64 addition then strict128-bit2*S<3*B. The original weighted_gate does not compute the first provider. The selected
module now supplies a conditional first-fold value from actual admitted map and
key-tree structures; neither API establishes the original ABI or consensus policy.

Build directly with actual pinned rustc1.94.1, edition2021 (no Cargo graph):

    rustc --edition=2021 --crate-name node115_weighted_fastfold --crate-type rlib lib.rs
    rustc --edition=2021 --test lib.rs -o /new/smoke

From repository root, tools/node115_weighted_fold_rust.py --rustc /pinned/rustc
--output /new/output performs real two-profile comparisons, compiled smoke,
three compiled mutants and raw own-archive repeat. Exact commands, target/source
hashes, pre-Rust frozen corpus, development failures and limits are retained in
research/work-items/RE-014-node115-weighted-fastfold-rust.

## Checked selected-key first fold

`selected::checked_selected_fold` consumes a `KeyCursor` over a validated
`KeyTreeView` and a `WeightMap::Flat` or `WeightMap::Tree`. The views borrow
actual rows/nodes; they preserve duplicate keys and structural key order.
`FoldOutcome::Complete { sum, consumed }` corresponds to first status1/basis=sum;
`Overflow { wrapped_sum, consumed }` corresponds to status0/basis=wrapped_sum.
A carry consumes the failing key and returns immediately; a later call resumes
from the retained frontier with a new zero accumulator. `remaining()` and
`last_yielded()` expose logical cursor observations, not raw native layout.

The selected module's source, frozen tests, conditional proof, chosen constructor
policy and actual Rust1.95.0 checks are in
[RE-008 evidence](../../research/work-items/RE-008-node115-checked-selected-fold/README.md).
Compile `lib.rs` directly as above with pinned Rust1.95.0 to run all42 tests.
The historical Rust1.94.1 harness described above includes a captured-instruction
evaluator and was not run for this extension; its module-copy integration was
verified separately using only reconstructed Rust. No runtime equivalence or
whole-node build is established.
