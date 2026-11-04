# RE-012: node115 bootstrap scalar continuation

- Component: `node-runtime`; RE-001 boundary/provenance and RE-012 startup.
- Target: Linux x86-64 node #115, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Reference main: `05bc2de303c05525b71e7e257426e741bc66a390`.
- Bounded result: independently authored scalar continuation in
  `src/node115-bootstrap-range/progress.rs`, with the existing range rlib as
  its explicit dependency. No Cargo graph, lockfile, imported source or target
  bytes are used to manufacture an implementation.
- Status: qualified value projections and static observations; original ABI,
  whole async behavior and integration remain unresolved. No gate is requested.

## Gap and source change

The existing `plan(lower,target)` models an already selected initial pair.
It does not compute the fresh saturated predecessor increment, the loop's
different entry relation, or the later fallback/record equality check. This
is an approved reconstruction gap, **not a production defect or failing base
test**. The old library, driver, tests and 53,038-row freeze are unchanged.
The extension exposes `initial`, `after_window` and `completion_check`.
The two branches of a completion check denote equality only, not completion
of the original async operation.

For example, initial predecessor 0 / target 30002 exits at the span gate,
whereas re-entry after endpoint 0 / the same target produces [1,100]. Reusing
the initial guard in the loop is observably wrong. MAX/MAX deliberately
remains [MAX,MAX]; this packet does not invent an end-of-domain stop condition.

## Reproduce

Run from the repository root with Python 3.12, Capstone Python binding 5.0.7
(core 5.0.1280), GNU objdump 2.47 and the authenticated pinned artifacts.
The retained GNU export covers the **whole** owning FDE. Its filename header
alone is redacted; no instruction bytes, operands or comparison masks change.
The public scripts authenticate both repository ELF parsers by SHA-256.

```sh
python -B research/work-items/RE-012-bootstrap-continuation-115/derive.py \
  --out work/bootstrap-continuation-derived
# Optional --target is a read-only path to the identical authenticated capture.
# Independently refresh the GNU export using a trusted native objdump:
objdump -D -j .text -M intel --insn-width=16 \
  --start-address=0x5a82670 --stop-address=0x5a89535 \
  artifacts/node/115/hl-node
```

The resulting 307,232-row TSV must hash to
`5400acd3ab3a11f288871062367c37b297f10d9a91e64059197e70014c748b70`.
`initial-freeze.json` is the untouched historical receipt from **before the
new checkout and extension existed**, with the old Rust explicitly acknowledged.
`derive.py` is a **post-authorship reproduction** and writes `derived.json`;
it never purports to recreate the historical timing.

Build the real dependency graph with a separately trusted, absolute rustc
1.95.0 and linker path, their SHA-256 values and installed Linux target core:

```sh
python -B research/work-items/RE-012-bootstrap-continuation-115/qualify.py \
  --repo . --out work/bootstrap-continuation-build \
  --vectors work/bootstrap-continuation-derived/frozen-vectors.tsv \
  --freeze work/bootstrap-continuation-derived/derived.json \
  --rustc /absolute/trusted/rustc --rustc-sha256 <sha256> \
  --linker /absolute/trusted/linker --linker-sha256 <sha256>
```

Use a fresh output directory. On Windows use a process supervisor with finite
deadlines and ownership-scoped descendant cleanup. The observed compiler was
rustc 1.95.0 (59807616e), LLVM 22.1.2, x86_64-pc-windows-gnullvm; exact tool
hashes, flags and commands are in `qualification.json`. Original 1.94.1
research qualification is not relabeled as a 1.95 run. Each subprocess has a
180-second timeout; the collection had a 900-second total limit, 300-second
phase limit and 180-second no-progress limit. No target binary, target
instructions, Linux output library or network service was executed/emulated.
Only the newly authored host Rust probes and unit executables ran.

## Native evidence and coordinates

All addresses below are ELF linked virtual addresses, not file offsets.
The owner FDE is [0x5a82670,0x5a89535): 28,357 bytes, 4,774 instructions,
body SHA-256
`993bd9a168f2e37e4cdc80092c5ea5e68a3bc0225098621c57e89fccb7bf57fc`.
Existing bootstrap/input-writers/limit-writers/block-fill/grant packets already
bind this body. There is **no new function-discovery or byte-coverage credit**.

`native.py` decodes every byte, checks the retained GNU partition against
fresh Capstone, inventories direct calls and relocation-backed indirect calls,
and conservatively links 15 byte-selector relative jump tables using all 256
possible byte values. Those supersets include adjacent data and invalid enum
values: they do not establish admitted states or declared table sizes.
Its intra-FDE graph assumes ordinary call fallthrough and callee-save behavior;
exceptions, re-entry and opaque helper memory effects are outside the proof.
All calls/relocations and table records remain available in generated output.

| Observation | Native sites and scope |
| --- | --- |
| State base | RBX receives entry RDI at 0x5a826b2 and is retained until return. |
| Selected pair | At 0x5a88391, conservative backward definition search finds only R14=RBX+0x278 at 0x5a88206 and R15=RBX+0x280 at 0x5a8820d. |
| Fresh entry | Load state+0x200 at 0x5a88165; INC 0x5a8816c / CMOVNE 0x5a88176 implement saturated +1. Save lower/target at +0x258/+0x260 (0x5a8818f/196), join 0x5a881cc and store +0x278/+0x280 at 0x5a881e0/e7. |
| Input stores | Selected fresh +0x200 comes from the qualified R13 alias store 0x5a8765f (last R13 definition 0x5a8760c = RBX+0x200); +0x1f8 from 0x5a87605. Only direct/qualified alias stores are covered. |
| Resume | 0x5a828b2..0x5a828c8 reloads +0x258/+0x260. Values may be inherited at invocation entry; no whole-future invariant is inferred. |
| Initial gate | 0x5a88391..0x5a883b4: target-minus-lower without borrow and >=30001 branches to 0x5a88d17. Otherwise lower<=target enters 0x5a83026; reversed enters 0x5a883c4. |
| Window | 0x5a83026..0x5a83054 stores min(target,saturating(lower+99)) at state+0x290. |
| Loop | 0x5a82ff3..0x5a83020 saturates old endpoint+1 into +0x288, then compares with target. It does not revisit the initial 30000 span check. |
| Equality gate | 0x5a883c4..0x5a88436: container +0x268, length at container+0x10, fallback at +0x110. Zero length OR zero computed last-entry address uses fallback unchanged. Otherwise load the record pointer; tag +0x28 == 0x8000000000000001 selects +0x60, else +0xb0, then saturated +1. CMP at 0x5a88433 / JNE at 0x5a88436 compares against retained target. |

`LastRecord` contains available logical fields, **not** the native struct.
`None` means the qualified fallback branches above, not a null *loaded* record
pointer. Readability, pointer ownership, allocation/layout and earlier lookup
effects are assumptions, not supplied by a fabricated container implementation.

## What follows equality (static observation, outside scalar API)

Equality calls 0x1629690 (clock-related result; separate ongoing work), formatter
0x5c9b830 and conditionally 0x635de30. Raw route byte 0x44 is written at
0x5a885d8 and joins 0x5a842a9. Mismatch builds the 0x141e3a0 carrier,
writes 0x2e at 0x5a88646 and reaches the same join.

Route 0x44 can initialize another phase and call waiter 0x5a897e0 at
0x5a8438a; it is not immediate successful return. Raw 0x45 at 0x5a84398
goes through 0x5a84537 (inner state 4, AL=1, BPL=5) to outer state byte
[RBX+0x1a5]=5 at 0x5a888ba. Other resource/drop branches remain conditional.

The waiter [0x5a897e0,0x5a8a1cc), 2,540 bytes / 468 instructions, hashes to
`99646f05de23478a72a44701b2bf5ea62dc5176cff29626205b74fc2fc250f67`.
It is already described by
[RE-001-node115-nv-stream-execution-wait-loop](../RE-001-node115-nv-stream-execution-wait-loop/README.md).
This packet rebinds its identity, cites that work and does not duplicate its
implementation. Its receiver-first/buffer check, raw 0x39/0x44 results and
0x45 pending route do not recover executor, I/O, timing or cancellation ABI.

## Comparison and negative controls

`initial-freeze.json` records 529 boundary + 100,000 deterministic raw-u64
rows for each of fresh and loop entry, plus 6,174 boundary + 100,000 raw-u64
rows for completion: **307,232 total**. A wide-integer mathematical oracle
and a separately written native-derived carry/subtraction/branch relation
agree before Rust authorship. They are by the same author; this is not an
independent peer oracle or captured-target execution differential.

Six counterfactuals alter selected native INC/immediate/Jcc relations and
each changes its witness: fresh INC 0x5a8816c, loop INC 0x5a83001, window SUB
0x5a8302e, tag immediate 0x5a883fd, record INC 0x5a8841d, JNE 0x5a88436.
They are static relation changes, not patched/ran target instructions.

Observed host libraries at opt-level 0 and 3 each preserve all **53,038**
legacy outputs and match all **307,232** extension expectations. The legacy
input SHA is `df540604564f0170091dad0d33f8320f872f8d502ac443f2d4be432df3b811ee`;
actual legacy output SHA is
`fab6185bf2936aa8b25e87950282f7bb6332074ff404f636efe9b45b26ef0089`
(lossless `legacy-output.tsv.gz`). Original 1-test + new 3-test unit binaries
pass in both profiles. Repeated host and Linux-target rlibs are byte-identical
within each target. These are comparisons of the independently authored
libraries with each other, not compiled-body equality to the captured node.

| Actually compiled source corruption | Differing rows / 307232 |
| --- | ---: |
| Wrapping fresh increment | 23 |
| Loop increment removed | 100506 |
| Initial guard reused in loop | 16870 |
| Wrong record tag | 7783 |
| Wrapping record increment | 441 |
| Incremented fallback | 52063 |
| Inverted equality | 106174 |

Raw stdout/stderr and command exit codes are retained in `qualification-logs.json`
and `qualification.json`; legacy stdout is referenced by its lossless archive.
No normalization masks or fabricated binary byte match are used.

## Failed collection and validation limits

The outer Windows Job supervisor run `25856010f19841308cf6a8497a77e809`
**failed-leftover-child**, despite the root qualification script exiting 0
after all comparisons. It terminated its own remaining descendants, positively
confirmed zero owned processes and released its matching lock. Member PID/name
details before cleanup were not recorded; the cause is unknown. This run is
not relabeled passed and the identical full build is not retried. A separate
read-only audit authenticated current source, rlibs, mutant source and original
stdout/stderr against their recorded hashes. See `collection-status.json`.
The original named D temporary/cache/home directories were later found absent;
actual temporary-file locations during that collection were not audited.
A subsequent Make temp-fallback warning was preserved, owned directories were
created and forward-slash paths verified without warnings by make doctor.
No exclusive D-temp claim is made for the original collection.

This supports the retained individual observations, **not a green overall
compilation collection**. Separate rustfmt and library/driver Clippy metadata
checks completed with zero owned processes.

The public post-authorship static derivation was actually rerun and reproduced
the frozen hash; its Job ended cleanly. Exact-head repository commands/results
are reported in the PR and D handoff. Required `make test` remains unrun here:
prior same-condition base runs are unresolved (including a mutation control
copying the 105,896,032-byte capture per relocation and timing out with no
progress). This packet does not silently waive that requirement or claim
hosted CI/container/full-suite success. Unrelated fixes belong to their owners.

No component mapped/built/behavior/identity gate, whole-module denominator,
native ABI, integrated node, release-compiler identity or whole-async
equivalence is claimed. Next question: close the remaining original container,
helper memory effects, ownership/drop and polling states before wiring these
qualified scalar relations into an actual bootstrap implementation.
