# Source phase and exact build admission

This is an additive implementation phase of PR1422. The published original20
files and immutable pre-code32 files remain unchanged. Read
[`SOURCE-PROOF.md`](SOURCE-PROOF.md) with
[`../pre-rust/CONTRACT.md`](../pre-rust/CONTRACT.md) and
[`../pre-rust/PROOF.md`](../pre-rust/PROOF.md). The new source implements the
complete supplied ordered-book/common-slab impact relation, both premium
formulas and one selected record projection. Native scheduler, selected
metadata/hash/set lookup, allocation, physical layout and helper/frame behavior
remain explicit premises, not new host features.

The source-authoring gate followed the independent pre-code review and exact
replay. It did not authorize compilation. This source/harness freeze precedes
any candidate compilation; a separate coordinator gate must identify its exact
SHA256 before the command below is run. This document describes planned checks,
not observed build outcomes. Future results must preserve any failed attempt.

## Actual graph and source

`src/node94-funding-premium-values` has exactly five admitted files, one library,
one integration-test target, no dependencies, no build script, and no workspace.
The actual lock was generated offline in a fresh isolated copy. Full locked
Cargo metadata confirmed exactly that package, its two targets and that copy as
workspace root. `LOCK-ADMISSION.json` records the six actual preparation commands
(three version queries, rustfmt, lock generation and metadata), with raw private
receipt hashes. No Rust candidate was compiled or executed by those commands.
The public metadata declares its logical path normalization; it is not claimed
byte-identical to the private raw metadata. The final locked graph is rechecked
in both clean build roots.

Production is independent of the Fraction/bisection pre-code oracle. It uses
u128 products, exact aligned integer sums and quotient/remainder rounding of
normalized significands. In particular the scaled oracle is a general positive
binary64 denominator; the narrower integer-count proof from funding-rate is
not reused. No dependency on that pending component exists. The three private
arithmetic tests cover integer ties/carry, 75/76-bit alignment boundaries and
a fractional denominator. Ten integration tests cover the shared slab, ordered
walk, field widths, saturation/cap/partial boundaries, active/fallback records,
rounding sequence and distinct new safe refusals.

`input_client.rs` imports the actual crate and calls `evaluate`. It parses only
stdin, accepts no arguments, does not read files or expected outputs, and uses
opaque IDs only to echo/deduplicate them. Both ordered slices refer to the same
constructed slot vector. Checked count arithmetic and equality with the actual frame length precede
entry/slot capacity allocation; field widths are checked before admitting each
struct value. Malformed input produces no partial output. The library itself
allocates nothing. The client/output buffers require successful finite host
allocation; no service, memory-exhaustion or allocator-equivalence claim is made.

## Planned qualification

After the exact build gate, run the frozen harness using its canonical path:

```sh
python3 -B source-validation/build.py \
  --toolchain /absolute/path/to/1.94.1-aarch64-apple-darwin \
  --out /tmp/a-fresh-impact-premium-directory \
  --private-map /absolute/private/path/impact-build-map.json \
  --source-freeze-sha EXACT_SOURCE_FREEZE_SHA256
```

Run from this packet's directory. Output must be a fresh direct child of the
canonical temporary directory. The private mapping file must be fresh and
outside this packet. The harness rejects source/driver/harness symlinks, admits
only frozen source and exact mutation text, and checks lexical and canonical
ancestor Cargo configuration/workspace paths. A fresh Cargo home, narrow
environment, offline/locked Cargo and pinned Rust bin/lib payloads prevent
project-dependent downloads or install hooks. `HOME` remains unchanged and is
not repurposed or recorded. Metadata must report the copied component itself as
workspace root. Selected external linker/SDK inputs are recorded before builds
and rehashed afterward; the OS/dyld and entire SDK are not claimed hermetic.

The harness performs one actual post-source static replay and compares it to
the immutable pre-code verification JSON. It then builds/tests the actual crate
in debug and release, directly links the input-only client against each rlib,
and compares every one of the frozen6034 output frames byte-for-byte. A second
fresh canonical root with the same relative layout repeats both build/value
passes. Raw rlib/client hashes are compared with no masks or normalization;
inequality is recorded, not repaired or concealed. Exact compiled artifacts
remain in their private build roots; public identities alone do not claim that
those binary bytes are distributed.

The planned source mutations are24 exact independently hashed edits:22 ordinary
supplied-value variants and2 explicitly labeled safe-policy variants. Each must
actually compile and produce a complete6034-frame stream that differs in both
profiles. A compilation failure, panic, timeout or missing output is not a
semantic kill. The two policy controls do not prove ordinary native call order
from value outputs. They test the separately documented scale/cycle refusal
policy. Mathematical false-model witnesses in the pre-code corpus are distinct
from these later compiled mutations; counts must not be conflated.

Ten comparator corruptions,22 malformed-input cases, one extra-argument refusal
and one valid empty stream test the evidence boundary. With all required checks
passing, the plan is198 child commands, including23 expected exit2 refusals,
52 complete value streams (four correct and48 mutated), and13 authored tests
per profile (three private plus ten integration). These are planned totals only.
The harness stops at the first required check failure and retains the observed
command and output before rejecting it. Any failure changes actual counts.

## Receipt and reproducibility limits

Every child stdout/stderr byte returned to Python is retained as content-addressed
deterministic gzip without rewriting. Commands, input hashes, source/driver
copies, compiler environments and incremental value observations are recorded.
On a timeout, the runner retains the partial streams attached to Python's
exception and records no invented child exit status. A launch error records the
actual exception text and no child exit status; that text is not child stderr.
It does not promise bytes unavailable to Python, descendant-process capture or
survival of abrupt parent termination. A private-home-path check occurs after
retention; a rejected run remains private rather than silently redacting bytes.

The installed Rust payloads are fully enumerated under bin/lib, with symlinks
separately admitted. Linker/selected SDK identities and actual command receipts
bound the host qualification, not the captured node's original compiler, ABI,
floating control state, economic policy, source types or instruction execution.
Runtime caches and private home paths must be excluded from the later public
publication manifest. No frozen historical file is rewritten to make a run pass.
