# RE-008: node115 proposer selection and history contract

Component: consensus. Author: 신준. Target: Linux x86-64 node115,
SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
All addresses are ELF virtual addresses. This contribution resolves the
conditional selection relation of the complete `[0x595cb30,0x595e5b8)` body
and its concrete history/weight/comparator helpers. The safe Rust projection
is under `rust/`, with no third-party dependency or invented recovered Cargo
graph. It is not a standalone node, a native ABI adapter or byte equivalence.

The two input rounds have different roles: RCX chooses history snapshots;
RDX selects the final key. Both history helpers support ring and tree storage,
warn at `max(sat(stake_base+2000),sat(execution+201))`, and continue after the
atomic warning increment. The later pipeline excludes first-snapshot keys,
forms a set union, saturates total weights, constructs rounded/FMA events,
sorts and replaces some events in ranked batches of three, then uses the full
selection-round remainder. Missing histories copy 72 scratch bytes; successful
selection and empty output write smaller byte-tagged footprints.

`PROOF.md` gives the formulas, path/load/store arguments and domain. Generic
container rebuild/clone/insert, deeper large sorts, consuming tree iterators,
runtime services and the resolved FMA3 environment remain explicit premises.
All 57 main calls are listed in `call-boundaries.json`, including failure and
unwind edges. Capturing their call targets does not establish their semantics.
No concurrent counter/lock scheduling result or native fault/unwind behavior
is claimed. The input images are value snapshots and the model makes explicit
safe refusals for invalid snapshots or unrepresentable allocations.

## Fresh node115 evidence

`bindings.json.gz` contains 28 complete FDE bodies (17,654 bytes), actual FDE /
CIE records, instruction streams, CFG edges, RIP data and relocation writers.
Eight instruction-bound calls through the actual naming slot `0x64e86f0`
occur in six complete caller FDEs. Including those callers, the independent
GNU archive contains 34 complete bodies, 38,606 bytes and 8,103 instructions.
The entire target hash and all 135,313 FDE / three CIE records are reparsed.
Two jump tables and seven constant/message spans are bound explicitly.
No exhaustive register-indirect caller reachability is claimed.

Historical node94 work is preserved only in commit
`b930b69f793f8e3676d60c0ceceb683b8c94ef8f`; it was never submitted after the
scope change. Its independently written mathematics was migration input.
Node115's separate rounds, representation alternatives, diagnostic counter,
weight saturation and output layout were rederived from its own bytes.
No active node94 artifact, retired helper or historical packet is needed to
replay this packet. Public Rust primitive source and licenses are retained in
`primary-source-files.json.gz`; their presence makes no source-version or
compiler attribution for the node. Official protocol countersearch and its
limits are recorded in `research-handoff.json` and `sources.json`.

## Reproduction

From the repository root, with the authenticated node115 artifact and the
repository's Python dependencies available:

```sh
python3 -B -O tools/proposer_selection115.py
PYTHONPATH=tests python3 -B -O -m unittest test_proposer_selection115 -v
python3 -B -O research/work-items/RE-008-proposer-selection-115/verify.py
```

The last command verifies retained raw outputs and independently rederives all
frozen expectations. It does not compile or run the node. To freshly compile
and run only the independent Rust, supply a real Rust 1.94.1 compiler and a
new ignored output directory:

```sh
python3 -B -O research/work-items/RE-008-proposer-selection-115/validate_native.py \
  --rustc /absolute/path/to/rustc \
  --out work/proposer-selection115-replay
```

The native client receives only `inputs.txt.gz` after decompression; it never
reads expectations. Commands use `--edition=2021`, one codegen unit, debug
information disabled, remapped build paths, opt-levels 0 and 3, each repeated.
The host qualification is aarch64 macOS; no x86-64 captured code runs. Repeated
object hashes establish reproducibility for these builds, not target equality.
No compiled-code comparison is registered because none was measured.

The GNU export can be reproduced with `export_disassembly.py` and an explicit
`GNU_OBJDUMP` if needed. This overwrites only its two deterministic export
files; the decoder is static. `disassembly-commands.json` preserves actual
commands and original output hashes. Native commands, exact stdout/stderr,
statuses and comparison records are under `validation/`; their compressed
archives preserve the exact bytes and hashes without one file per stream.

## Qualification and limitations

`freeze.json` binds 9,243 cases before the first node115 Rust adaptation:
1,040 delayed histories, 1,934 exact-ratio binary64 arithmetic cases, 120 raw
event-order cases, 610 weight preparations, 571 materialized schedules, 260
two-history/image cases, 334 diagnostic cases and 4,374 ring layouts/queries.
Historical own Rust had already existed and was inspected; that chronology
is explicit. The newly frozen corpus includes the earlier learned union
counterexample shapes. It has no post-node115-source supplement.

The first four correct builds matched all 9,243 records each. The first
qualification then stopped after 39 effective compiled mutants because the
validator searched for a one-line diagnostic expression that rustfmt had split
across lines. That is a validator-anchor error, not a target/model mismatch or
an effective mutation. `validation/native-initial/` retains the exact failure,
commands, 206 raw streams and original validator. Its traceback copy replaces
only the local repository prefix; the original hash and transformation are
recorded. Source, client, oracle and frozen fixtures were unchanged for the
fresh final qualification. Final results and integration checks are recorded
in `validation/summary.json`. All four final builds matched 9,243 records each
(36,972 observations); all 47 compiled mutants returned normally with observed
value mismatches. Repeated object hashes agreed within each optimization level.
Four comparator and two archive corruption controls were rejected. The final
raw archive contains 244 exact streams, alongside the preserved initial 206.

Six separately compiled tests check snapshot order, ring admission, missing-
first short circuit, two diagnostic increments, scratch padding, arithmetic
admission and refusal before an unrepresentable schedule allocation. Focused
static tests corrupt target bodies, FDE bounds, constants, jump tables and an
actual relocation writer; comparator and archive corruptions are also rejected.

These are independent-formula/static-derived expectations, not observations
from executing the target. Small/native tests do not prove the explicit
generic-helper postconditions, source identity or whole-component equivalence.
The task leaves all acceptance gates unchanged. The remaining material work
is closure of those generic helper/runtime and alternative FP paths, together
with native layout integration; this packet does not count them as complete.

The packet was preserved on the initial c3b77a8e base, then rebased onto the
115-only migration commit `8fd8db680ec4bfef40996e5616bce3d5156d0b86`. On that
base, 55 focused tests and optimized packet replay passed. `make doctor`,
`verify`, `catalogue-check` and `reproduce` passed after local LFS materialization,
the documented GNU tool environment, and official regeneration of the new
29-work-item inventory. Initial environment/pointer/stale-inventory failures
are retained in `validation/integration/`. These checks precede the separately
recorded full suite below. The native source, driver, oracle and fixtures did
not change on rebase.

Independent review reproduced a packaging-verifier gap at commit `638695d4`: a
full replay still passed with unlisted files/directories and same-content or
dangling symlinks in the packet fixture. Exact prior verifier and result streams
are preserved in `validation/manifest-review/`. The corrected checker requires
a unique, closed file/directory inventory and ordinary path components beneath
the repository, including the two task-owned external tool/test paths. Six new
temporary-tree control methods cover the gap and malformed/missing rows. This
assumes the filesystem remains stable during verification; it is not a defense
against concurrent path replacement. Rust, oracle, client and frozen/native
results are unchanged. The full repository `make test` passed on fixed commit
`a309180b11d94539885d60318d5a64d4ddbd1f01`: 77 test files, 409 reported tests,
three reported skips, exit 0 in 1,077.721 seconds. `validation/full-suite/` keeps
the complete hashed inventory and exact logs. Later additions are evidence and
documentation only; earlier 55-test results remain scoped to their head.

The independent review in `peer/review.json` authenticates all 34 bound bodies,
38,606 bytes / 8,103 instructions, all 61,001 RELA records and eight incoming
call sites. A different CPython/Fraction computation matches all 9,243 frozen
expectations. The fixed manifest function also rejects five independent
corruptions. These peer checks do not reexecute native builds or prove the
explicit generic-helper/runtime premises. Portable scripts and publication
hashes preserve their exact scope.
