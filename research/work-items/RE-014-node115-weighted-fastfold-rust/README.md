# RE-014: Rust for the node115 two-span checked weight fold and strict wide gate

> Current #115 migration (2026-11-02): this implementation was rebuilt and
> compared at opt-level 0 and 3 after retiring the older node and trimming
> its shared tooling. `migration-validation.json` records the fresh run and
> compiled mutation controls. Historical blocker reports below describe the
> original environment; they do not require the retired binary. Original
> negative results and target-bound records remain unchanged.


Component: source-associated quorum-policy arithmetic, conditional post-provider
fast path. Target node115 SHA256a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301,
105896032bytes. Basee5c9b6436876b2a4a39daef813171f9879317699; freezecf0525ac.
Credit merged#987 / unchanged RE-001-node115-weighted-comparison. Its native
records and theorem are dependencies, not newly mapped bytes. No inferred
unlicensed source is copied; new Rust/evidence code is independently authored MIT.

## Contract and exact boundary

The original packet binds four full FDEs(1657bytes/422instructions), source
Locationbase/src/quorum_policy.rs:72:9, lookup slots and raw first-helper status.
It supplies no Rust. We regenerate its full bindings unchanged; old exports,
source pins and negative results remain intact. This implementation covers the
**closed fast two-span suffix** of FDE0x422e280..0x422e403, bodySHA256
c7ab574649057fbb00d19e8c935ccaa2cff819f9a238eeb90547dc721d3acb90.
Evaluation starts0x422e2d9 after the first helper has returned and raw iterator
tag2 selected the fast path. It stops0x422e3f5 before the epilogue.

The explicit boundary is retained raw first_status/basis plus two valid,
nonwrapping readable row spans. Native rows have stride32 and weight+24.
The first span is exhausted, then the native descriptor swap at0x422e320
loads the second span. Both can be empty. The evaluator initializes exactly
these descriptor qwords and row weight words, never a helper return callback.
It allows only the four qwords at stack+8..40 to be written; row data is
read-only. Calls and out-of-suffix PC transfers are rejected. No provider,
lookup, generic next adapter, original cleanup or captured process is executed.

The observed relation is: checked u64 sum S over first then second span;
any addition carry selects false. On normal completion first_status must be
**exactly1**, checked after stream processing. Then return `2*S < 3*basis`
using full unsigned128-bit products. Zero/zero and ties are false. At all-MAX,
high limbs matter. Bounded products fit below2^66, so Rust u128 arithmetic is
exact. Nonnegative weights mean sequential checked-add success is equivalent
to the mathematical sum fitting u64. This is a manual scalar argument and
actual finite comparisons, not a machine-checked compiler proof.

The source takes slices of weights as an own safe interface. It does not claim
the original32-byte row/iterator ABI, first checked-fold implementation, key
lookup/membership/duplicate rules, a validator-set interpretation, original
panic/ownership/unwind, or consensus/replay correctness. Generic iterator tag
routes and malformed raw metadata are outside the claim. This is not node94.

## Evidence, active comparison blocker and controls

The previous script is static-only and cannot link/test Rust. The reused
integer Image constructor also binds node94-only diagnostic slots (the same
digest-specific constructor failure documented by PR1908). A small local
view bridges the existing generic ELF/FDE/relocation parser to the existing
integer decoder using only actual node115 maps and slots. It fabricates no
slot/helper and changes neither shared module. Independent FDEs match all four
original owners;37selected raw instructions are independently length-decoded
with Capstone5.0.6. Original full body/call/source/relocation bindings regenerate.

FREEZE pins12804distinct(status,basis,split,weight-sequence) rows before Rust:
11268exhaustive short cases (length0..3, four boundary weights, every split,
four statuses, nine bases), plus1536public deterministic longer cases with
empty/half/full splits. Rust opt0/opt3 separately linked clients each match
all12804results. Long corpora/products regenerate outside Git; their hashes
are pinned. No normalization mask is applied.

Four actual byte changes bypass the carry exit, alter factor3, flip wide
condition or change required status. Each changes an observed result and the
old static binding rejects it. Three real compiled mutations change checked
sum to wrapping, discard the left product's high limb, or accept ties; they
mismatch894/262/14rows and all fail compiled smoke(exit101).

An initial strict sandbox wrongly rejected actual descriptor stack stores;
probe exited1 in7.486wall seconds. Allowing only the measured four-qword stack
role (including spill/reload bounds) yields corrected probePASS8.524wall seconds.
The initial13-row smoke lacked the high-limb counterexample: full-corpus
comparison killed that mutant, but smoke did not, so the first build exited1
in112.807wall seconds. A **previously frozen corpus row** was added after
implementation to smoke; it was not a new expected value. Original13-row
freeze/history is preserved; final14-row smoke and an unchanged production
library were freshly rebuilt. Corrected full buildexit0 in122.677wall seconds.
Own opt3 archives are raw-identical. No failed attempt is relabeled PASS.

Compiler: actual rustc1.94.1(e408947bfd200af42db322daf0fadfe7e26d3bd1),LLVM21.1.8,
macOSaarch64 host. Direct no_std rlib builds use opt0/opt3, overflow checks and
codegen-units1. No new Cargo graph, dependency version or fabricated workspace.
Own-host archive equality is not original x86-64 code/ELF identity.

## Reproduce and remaining checks

From repository root, Python3.12.14, Capstone5.0.6 and actual pinned Rust tools:

    python3 tools/node115_weighted_fold_rust.py --rustc "$RUSTC" --output /new/output
    python3 -m unittest tests.test_node115_weighted_fold_rust -v
    "$RUSTFMT" --check --edition 2021 src/node115-weighted-fastfold/lib.rs src/node115-weighted-fastfold/input_only_driver.rs
    "$CLIPPY" --edition=2021 --crate-type lib src/node115-weighted-fastfold/lib.rs --emit=metadata -o /new/lib.rmeta -D warnings
    "$CLIPPY" --edition=2021 --test src/node115-weighted-fastfold/lib.rs --emit=metadata -o /new/test.rmeta -D warnings
    make doctor verify test catalogue-check reproduce

Capture identity, full native records, raw instruction rows, corpus hashes and
smoke-copy equality are checked before compiler invocation; output must be new.
build-result.json preserves exact commands/source/compiler/output identities
with private path spellings replaced only. Five focused tests PASS79.719wall seconds; pinnedfmt and Clippy library/test
PASS; fresh catalogue-check PASS. Combined command exit0 in123.915wall seconds,
with nonfatal xcrun cache warnings retained in validation-results.json. Shared signed-input/import/inventory checks
reuse completed#1831 only for explicitly unchanged paths; not new-code tests.
Full make test has not completed and awaits upstreamCI; queued is not PASS.

Offline Python instruction evaluation is explicitly authorized. No native
capture, Unicorn, network, wallet/signature/chain action, fake callback, imported
change, first-party byte credit or full component gate is introduced. Local
jobs run serially at10%active wall-time duty with command limits; setpriority
is unavailable, and exact aggregateCPU percentage is not promised. Next close
the actual first fold and key/iterator helpers before integrating a full policy.
