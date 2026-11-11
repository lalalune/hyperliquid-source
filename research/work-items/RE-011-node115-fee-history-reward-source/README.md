# Fee-history reward construction and ordered selection

This partial contribution to issue #3922 supplies independently authored Rust
for two connected numeric stages in node #115 fee-history processing. Existing
research already maps both stages; this work implements their bounded contract
and qualifies it with new target-bound instruction checks. The issue remains
open and no component gate changes.

Target: `artifacts/node/115/hl-node`, Linux x86-64, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Addresses are linked ELF virtual addresses, FDE ends are exclusive; publication
base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.

## Scope and prior work

The merged [reward-construction packet](../RE-001-node115-fee-history-reward-construction/README.md)
(#3267) recovers the constructor at `0x2355610..0x23558f1` and its caller
`0x2a20e11`. The [fee-history adapter](../RE-011-evm-fee-history-115/README.md)
maps the post-sort selection at `0x2a20ff8..0x2a210a6`. The earlier
[small-input ordering packet](../RE-011-node115-small-input-ordering/README.md)
(#3205) covers a selected sorter path. We do not reimplement or assert that
all native sort paths use one ordering: callers supply already ordered rows.

`build_reward_rows` consumes typed fields corresponding to the active portions
of 336-byte transaction rows and cumulative u64 fields of 40-byte receipt rows.
It takes the shorter input length and starts the previous cumulative value at
zero, matching the selected caller. The cap is the zero-prefix cap if the raw
u128 prefix is zero, otherwise the other cap. The reward is the unsigned
saturating difference from a u64 base fee; when prefix is at least two it is
also capped by the priority field. Each gas weight is the checked difference
from the preceding cumulative value. Underflow is returned as an owned API error
with an index; native code goes to its panic path, so error type and unwinding
are not claimed equivalent. Unpaired receipt rows are not consumed by this
constructor. Native receipt cloning may already have inspected them.

`select_ordered` receives a slice in the caller's chosen order and an independent
u64 total. It computes `(percentile * (total as f64)) / 100.0`, performs the
saturating binary64-to-u64 cast, and advances a forward-only row cursor until
accumulated weight meets the threshold or the last row is reached. It returns
the current u128 payload per percentile. Empty rows yield zeros; weight
addition overflow becomes an owned API error. Equal thresholds do not advance;
later decreasing percentiles never rewind. The caller's selected total derives
from another input vector; equality with the weights is not assumed.

The source composes these stages through explicit typed inputs. It does not
perform native sorting, clone receipts, validate the percentile request, fetch
blocks, serialize a response, invoke a backend, or implement the runtime panic,
allocation, I/O or original ABI. Values and units retain positional labels.
Valid storage, normal helper return and IEEE binary64 round-to-nearest,
ties-to-even with gradual underflow and separately rounded operations are
premises; the target's floating environment setup is not established. Arbitrary
synthetic prefixes are arithmetic test inputs, not proven native enum states.

## Evidence

The new verifier authenticates the complete image digest, enclosing FDEs,
five selected windows (1,213 bytes / 270 instructions) and 50 semantic facts. It pins the zipped
count and initial state, constructor fields/strides, underflow branch and
u128 cap comparison, unsigned u64-to-binary64 conversion constants, threshold
cast, cursor advance and checked weight addition. Negative controls change the
selected comparison, constants, strides, operands and branch encodings in 16 controls after
the whole-image/window checks are bypassed; the deeper fact checks must reject
each. See `verification.json` for exact selected counts and results. The
retained windows establish bounded static relations, not full owner coverage
or target execution.

The MIT Rust crate `src/node115-fee-history-reward` has no external dependencies
and forbids unsafe code. Tests include 10,000 deterministic u128 constructions
checked against a separately written two-limb arithmetic oracle; 1,200
synthetic selection cases are compared with the previously existing Python
selection model, including NaN, infinities, negative values and large totals.
Those comparisons and the original operand-derived relations are independent
models, not native differential execution. An explicit integration test uses a
supplied row ordering, preserving the sorter boundary. Seven tests also include
u64 totals around `2^53` and `u64::MAX`. Independent static review of the
conversion sequence confirms its two bias constants and final binary64
addition; that review does not execute the captured target.

## Reproduce

```sh
PYTHONPATH=tools python3 research/work-items/RE-001-node115-fee-history-reward-construction/relations.py
python3 research/work-items/RE-011-node115-fee-history-reward-source/reference-fixtures.py
python3 research/work-items/RE-011-node115-fee-history-reward-source/verify.py
cargo +1.95.0 test --offline --locked --manifest-path src/node115-fee-history-reward/Cargo.toml
cargo +1.95.0 test --release --offline --locked --manifest-path src/node115-fee-history-reward/Cargo.toml
cargo +1.95.0 clippy --offline --locked --all-targets --manifest-path src/node115-fee-history-reward/Cargo.toml -- -D warnings
cargo +1.95.0 fmt --manifest-path src/node115-fee-history-reward/Cargo.toml -- --check
shasum -a 256 -c research/work-items/RE-011-node115-fee-history-reward-source/MANIFEST.sha256
make doctor verify catalogue-check reproduce
```

The static verifier uses Python 3.14.7 and Capstone 5.0.7 from an existing
audited environment; no dependencies are installed. Full unfiltered
`make test` is not run because discovery includes captured-instruction
emulation. No target code was executed or emulated. Runtime ABI, native panic
and error projection, whole-message fee-history and component equivalence
remain unproved.

Implementation, static packet and GitHub/browser work: OpenAI `gpt-6.1-terra`,
`codex-desktop`. Independent original-instruction review: OpenAI `gpt-6-astra`,
`codex-desktop`. Existing project-authored ELF helpers and the prior Python
selection model are credited and remain unchanged.
