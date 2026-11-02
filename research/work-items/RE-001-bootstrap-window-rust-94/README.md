# RE-001: Rust for the selected node94 inclusive bootstrap window

Target node94 SHA-256:
3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f.
Base e5c9b6436876b2a4a39daef813171f9879317699. Component: node-runtime /
bootstrap selected arithmetic, not a complete network bootstrap implementation.

## Gap and bounded change

Merged #588, tools/bootstrap_window.py and the unchanged
RE-001-bootstrap-window-94 packet establish the native relation but contain no
Rust implementation. This implements that one complete selected relation;
equal/ahead/saturation/minimum are one family, not separate PRs. The original
packet's whole owner export, SHA256SUMS, FDE/CIE coordinates and negative results
remain untouched. No unlicensed inferred source was used or copied.

Owner FDE [0x4389070,0x438a38c), body SHA-256
78db20a2c3de64e35135b7730c8b45e77a3b551674136401c6f2de70f4d5f00f.
Selected arithmetic [0x43892a6,0x43892f0); equality branches to 0x4389c32,
unsigned-ahead to 0x4389e32. These are original ELF virtual addresses, not
file offsets or proof of original source ownership. Full native instruction
context remains in ../RE-001-bootstrap-window-94/owner.capstone.txt.

For raw current<target, return the inclusive interval
[current+1,min(target,saturating(current+100))]. For equality/ahead retain
distinct selected outcomes; their continuation behavior is not recovered.
current<target proves the first addition cannot overflow. The end is inclusive,
with at most 100 elements, including near-u64-MAX cases. The earlier lag gate,
source field types, original memory stores/ABI, async states, peer selection,
responses, state advancement and later helpers are excluded.

## Expectation provenance and real comparison

FREEZE.json and the compact fourteen-row smoke fixture were committed at
52df58bf before production lib.rs existed. A prior UNVALIDATED draft did exist,
as the freeze explicitly records; no pre-draft authorship claim is made.
Expectations come from the unchanged actual-byte arithmetic decoder plus
separate big-integer interval equations, not from the new Rust implementation.
The full node identity, owner bytes and original accepted records are checked.

There are 106,649 distinct synthetic current/target pairs: the credited
325x325 low/near-MAX/bit63 grid plus 1,024 reproducible public pseudorandom pairs.
All actual selected-instruction outcomes match independent interval equations.
The full input/output SHA values are frozen; large deterministic corpora
regenerate outside Git. No live node state or fixture is read.

Real rustc1.94.1 opt0/opt3 libraries with overflow checks enabled are separately
linked to an input-only client. Both match all 106,649 rows. The ordinary
compiled unit test reads only the fourteen frozen smoke rows. Three compiled
mutants (window size, wrapping end, equality route) mismatch 31,174 / 4,950 / 325
rows respectively; all three also fail real compiled smoke assertions (exit101).
Same-basename opt3 own rlibs are raw-identical, without normalization. This is
host arm64 macOS reproducibility, not native x86-64 code-byte equivalence.

Three actual selected-code immediate edits change ordinary and near-MAX
outcomes, including a threshold edit that wraps the end to zero.
native-controls.json preserves inputs and before/after results. The old binding
tests still reject changed opcodes, identity, FDE, stores and immediates.
This uses separately authorized offline Python instruction evaluation, not
captured ELF execution, Unicorn, helpers, filesystem/network work or node calls.

## Reproduce and validation limits

From the repository root with authenticated inputs, the normal Python
environment, and the pinned actual rustc1.94.1 toolchain:

    python3 tools/bootstrap_window_rust.py --rustc "$RUSTC" --output /new/output --binary artifacts/node/94/hl-node
    python3 -m unittest tests.test_bootstrap_window_rust tests.test_bootstrap_window -v
    "$RUSTFMT" --check --edition 2021 src/node94-bootstrap-window/lib.rs src/node94-bootstrap-window/input_only_driver.rs
    "$CLIPPY" --edition=2021 --crate-type lib src/node94-bootstrap-window/lib.rs --emit=metadata -o /new/port.rmeta -D warnings
    "$CLIPPY" --edition=2021 --test src/node94-bootstrap-window/lib.rs --emit=metadata -o /new/test.rmeta -D warnings
    make doctor verify catalogue-check reproduce
    make test

build-result.json retains compiler identity, source hash, commands, actual
profiles and mutants. $REPO/$OUTPUT/$RUSTC replace path spellings only.
No original code operand is masked. The library is dependency-free no_std,
without a fabricated root Cargo graph or placeholder node.

The operator requested minimal laptop CPU. Local commands ran serially in a
process group with 10% active wall-time duty cycling and per-command wall bounds.
The OS denied nice/setpriority, so lower priority is not claimed. The command
supervisor is outside this PR; no repository tooling or workflow is changed to
implement that personal resource preference. Do not confuse wall time under
this limit with unrestricted performance or exact aggregate CPU usage.

Observed focused validation: 10 tests PASS in 63.146 wall seconds under the cap;
pinned rustfmt and Clippy library/test configurations PASS. Required safe/full
check completion states are separately recorded in validation.json and the PR.
No pending, interrupted or merely queued result is a completed full-suite PASS.
No shared first-party byte credit or catalogue/full-scope gate change requested.

Next close response-driven state advance and caller/resumption lifetime before
integrating this standalone scalar relation into a source-built bootstrap path.
