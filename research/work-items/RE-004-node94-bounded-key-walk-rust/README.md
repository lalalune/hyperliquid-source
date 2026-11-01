# RE-004: node94 key-walk stored triples and terminating cycles

This contribution independently reconstructs the complete 106-byte leaf
`[0x1b26100,0x1b2616a)` as dependency-free `no_std` Rust. It resolves the
Rust gap left by the [foundation packet](../foundation-bounded-key-walk-94/README.md).
Target node #94 is 91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`;
base is `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.

The helper selects three stored qwords while following node links. Its
three paths have different layouts: `[first,index,key]`,
`[stopping,index,previous_gate]`, or `[0,last_node,last_index]`. The new
`raw_triple` API preserves those distinctions, the full-u64 initial
comparison, unsigned16 later comparisons and wrapping index increments.
It returns the selected stored values, not the original out-pointer.

## Domain and proof

The [proof](PROOF.md) covers stable finite graph snapshots with unique
nonzero node IDs, arbitrary u64 key/index and arbitrary u16 gate words.
IDs are opaque labels that may retain observed pointer bits; this code
does not establish their native pointer validity. A successful projection
requires snapshots only for nodes actually read. No field meaning,
ownership, source type or complete caller purpose is inferred.

Cycles that stop at a gate are supported. The closing edge is tested
before the N-edge bound; N failed nonnull transitions through an N-node
map prove a repeated cycle whose fixed gates can never stop. The safe
API then refuses with `NonterminatingCycle`. This refusal, map admission
and `MissingNode` are new safe-API outcomes, not original returns or
invented stored triples. The original stable walk has no return on the
proved nonterminating cycle. Missing snapshots do not assert that the
original pointer was invalid; they mean the projection lacks needed data.

All original output stores occur after the final reads. Their selected
values are therefore unaffected by output/input aliasing, but the actual
stores can mutate original nodes/records afterward. This read-only
snapshot API does not reproduce those side effects, original ABI,
volatile/concurrent memory or fault behavior.

The independent oracle first enumerates the functional-graph orbit and
its first closing edge, ignoring gate outcomes, then selects the first
strict adjacency barrier. A recorded later missing node or repeat cannot
override an earlier stopping gate. Index arithmetic uses unbounded
integers followed by modulo 2^64, separately from the Rust's bounded loop
and wrapping addition. No instruction, register or flag evaluator is used.

`frozen/ORACLE-FREEZE.json` was created at
`2026-11-01T20:18:52.938636+00:00`, before Rust source existed. It binds
the unchanged oracle source, static facts and uncompressed input/output
hashes. Freeze creation refuses existing Rust or an existing freeze.
The frozen source retains harmless trailing blank lines: default
`git diff --cached --check` reports only `blank-at-eof`. A command-scoped
check with that one rule disabled passes; the frozen bytes are preserved.
No unlicensed inferred implementation was read or copied. New code/prose
use the root MIT license; retained artifact bytes/disassembly keep their
original rights.

## Complete static evidence

Full target identity, the 29-instruction leaf, six following padding
bytes and eight preceding gap bytes are authenticated. The complete
957-byte caller `[0x25767b0,0x2576b6d)` decodes to 213 instructions. Its
call at 0x2576999 is an actual instruction boundary, immediately preceded
by RDI=R13 and RSI=R15 setup. GNU objdump independently retains the full
leaf/caller disassembly and selected frame records.

The leaf FDE `+0x2e56c` points to CIE0. The caller FDE `+0x3eb2cc`
points to a different zPLR CIE at `+0x2dc714`; both actual CIE records
are checked, rather than assuming a shared CIE. Full .text direct-e8
scanning (70,370,352 bytes) finds this one call. All 80,300 RELA records
contain no addend naming the leaf. These scans do not close indirect
references. Caller exception handling and wider behavior remain outside
the reconstruction. The leaf itself has no callee or constant-table gap.

Only `src/node94-bounded-key-walk/` and this packet change. Prior evidence,
pins, generated catalogues and progress gates remain intact. The final
live overlap check found no match among 78 open PRs (including draft/
review state), zero open issues and 20 recent merges; `overlap.json`
retains that inventory. Existing `src` contained no implementation of
these addresses or this key-walk family.

## Actual native validation

The input-only driver receives node snapshots, root ID, index and key.
It receives no expectations and accesses no captured binary. Comparison
is external. The 96,927 frozen cases across 4,615 distinct supplied maps
are divided explicitly:

| Outcome | Cases |
| --- | ---: |
| Initial key stop | 10,365 |
| Later adjacency stop | 25,956 |
| Null successor exhaustion | 30,432 |
| New nontermination refusal | 29,610 |
| New missing-snapshot refusal | 396 |
| New invalid-map refusal | 168 |

There are 66,753 successful stored-value cases and 30,174 safe-API refusal
cases. The corpus exhausts all successor assignments on one through three
labeled nodes, rooted at the first label, crossed with gate pairs
`(0,0),(0,1),(1,0),(65535,65535)`. Additional maps cover u16 power/sign/
equality edges, chains and cycles up to 257 nodes, final closing-edge
stops, reordered map rows, missing/unread successors and index wrapping.
The proof covers arbitrary finite admitted maps; the corpus is not
claimed to exhaust every graph or word assignment.

Installed rustc 1.94.1 (`e408947bfd200af42db322daf0fadfe7e26d3bd1`,
LLVM 21.1.8) built the library and driver twice at opt-level 0 and twice
at opt-level 3. All four builds match all cases: 387,708 row comparisons,
zero mismatches. Repeat rlib, client and stdout hashes match within each
optimization level. Native host: aarch64-apple-darwin on macOS 27.0.1.
Python 3.14.3 ran validation under `-O`; guards do not depend on assertions.
Original x86 ABI and cross-host binary reproducibility are unmeasured.

Twelve wrong variants actually compile and run against the same driver:

| Variant | Mismatched rows |
| --- | ---: |
| Initial equality stops | 13,440 |
| Narrow initial key to u16 | 20,340 |
| Signed initial comparison | 27,582 |
| Signed later word comparison | 16,755 |
| Later equality stops | 29,433 |
| Retain original key at later stop | 24,435 |
| Saturating index | 14,810 |
| Increment index on initial stop | 10,365 |
| Exhaustion stores first node | 10,257 |
| Exhaustion stores key instead of index | 27,728 |
| Reject closing edge before its gate | 8,094 |
| Precheck unread successors | 150 |

All 8,094 closing-edge mismatches change successful outcomes. A self-cycle
with e4=0, e6=1, key=1 and index=0 must produce `[node,1,0]`, while that
mutant refuses. Eager successor validation changes 24 successful outcomes;
its other 126 mismatches change refusal information. For nodes
`1 -> 2 -> missing99`, with words `(0,0)` then `(0,1)`, key/index zero,
the correct triple is `[2,1,0]` and no snapshot of 99 is needed. The
mutant incorrectly refuses `MissingNode(99)`.

These successful-case counterexamples are retained separately in
`observed/selected-success-controls.json` and rechecked against the raw
native outputs. One corrupted expected row gives exactly one mismatch
against actual unmodified native output. Fifteen structural mutations
bypass only whole-file SHA admission and fail downstream body, CIE/FDE,
padding, caller or relocation checks. The artifact itself is not altered.

## Reproduce and audit

From the repository root with materialized pinned artifacts and installed
Python/Capstone, rustc 1.94.1 and GNU objdump:

```sh
python3 -B -O research/work-items/RE-004-node94-bounded-key-walk-rust/validate.py
python3 -B -O research/work-items/RE-004-node94-bounded-key-walk-rust/verify_recorded.py
python3 -B tools/foundation_bounded_key_walk.py --check research/work-items/foundation-bounded-key-walk-94/evidence.json
python3 -B -m unittest tests.test_foundation_bounded_key_walk -v
/opt/homebrew/opt/rustup/bin/rustfmt +1.94.1 --check --edition 2021 src/node94-bounded-key-walk/lib.rs src/node94-bounded-key-walk/input_only_driver.rs
env PATH=/opt/homebrew/opt/binutils/bin:/opt/homebrew/opt/rustup/bin:$PATH make doctor verify catalogue-check reproduce
shasum -a 256 -c research/work-items/RE-004-node94-bounded-key-walk-rust/MANIFEST.sha256
```

The validator accepts `--rustc`, `--objdump` and `--output` overrides,
but keeps the compiler version/commit check. It uses standalone rustc,
not an invented Cargo workspace or dependency lock. Builds and expanded
inputs stay in ignored `work/node94-bounded-key-walk/` (about 28 MiB).
Frozen/observed `.gz` files use existing Git LFS attributes.

`observed/results.json` binds source/build/output hashes and control
results. `commands.json` records exact arguments, exit status and raw
stream hashes using `/repo` for the worktree. One deterministic
`raw-streams.json.gz` archive retains 104 exact stdout/stderr streams as
base64 plus SHA-256. `verify_recorded.py` independently validates all
streams, all 16 native-run mismatch counts and selected successful-case
counterexamples. GNU frame stdout is explicitly excerpted separately in
`target.frames.txt`, retaining both CIEs and both FDEs.

The legacy checker, ten focused tests, rustfmt and
`make doctor verify catalogue-check reproduce` passed. Their logs are in
`observed/repository-checks.json.gz`; repository path redactions use
`/repo` and `<home>`, with original/retained hashes labeled separately.
No duplicate full test sweep was launched, and the coordinator's separate
run is not claimed here. Captured execution/emulation, hosted CI,
target-byte equivalence, full caller behavior and component gate
completion remain unmeasured or outside scope.

Authorship tooling: OpenAI / Codex. The exact model identifier is not
exposed by this runtime and is not invented.
