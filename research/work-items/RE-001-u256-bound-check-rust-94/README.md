# RE-001: u256 nonzero comparison and actual fixed-bound wrapper

This closes the unimplemented Rust gap in
[`foundation-nonzero-below-94`](../foundation-nonzero-below-94/README.md), together
with its actual 104-byte wrapper. The new independent safe `no_std` component
recovers the full unsigned comparison and four difference words, then the
wrapper's post-call 32-byte zero reduction. It is one closed 173-byte algorithm
family, not a claim on adjacent arithmetic leaves or the other callers.

Target: node #94 `artifacts/node/94/hl-node`, 91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Base: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.
Pinned reference: `999556f6e0a474b8312db96ec3149e1c44e97c23`.
Author: 신준. New implementation, proof and oracle are independently authored
MIT project work; no unlicensed inferred implementation was read or copied.
Provider/client: OpenAI/Codex. Exact model ID is unavailable in this session and
is not invented. Publication and registration are handled separately by the parent.

## Recovered behavior and scope

| Complete linked ELF range | Bytes / instructions | Recovered observation |
| --- | ---: | --- |
| `0x565dd80..0x565ddc5` | 69 / 19 | RAX is `0 < A < C`; RDX=1; RSI is unsigned borrow mask; R8..R11 are `(A-C) mod 2^256` |
| `0x5651e50..0x5651eb8` | 104 / 27 | Calls the helper with exact N, then includes zero: RAX=`A<N`, RDX=`A==0`; preserves RSI and difference words |

N is the 32-byte little-endian constant at `0x9186a0`:
`73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001`
as an unsigned integer. All input word patterns are admitted. Nothing in the
proof assumes reduced, canonical, signed or nonzero operands.

The APIs take four-word snapshots and return seven full-width numeric data
register observations. They do not implement a native pointer ABI. Stable
ordinary readable spans and snapshot consistency are required for correspondence;
partial or exact operand aliases are permitted. The wrapper's control stack must
be valid and disjoint, and its constant must retain the exact read-only bytes.
No data store occurs. SIMD registers, flags, control state, fault behavior,
concurrency and MMIO are excluded. [PROOF.md](PROOF.md) gives the universal borrow
induction, the wrapper's byte-union reduction, load order and domain in full.

The source is [`src/node94-u256-bound-check`](../../../src/node94-u256-bound-check/README.md).
Its final `lib.rs` SHA-256 is
`1200781de4d2e2d2c60f316de6721f8698958afd8df6a8fb61323e89e9674d89`.
The prior packet correctly notes that no difference is stored to memory; the
new API explicitly exposes its observed register values, without inventing an
original multi-value source signature. A prior prose gap count is corrected only
in this new proof; historical evidence remains untouched.

## Static closure

`static_evidence.py` authenticates the full target, parses all 121,299 FDEs and
3 CIEs, checks unique exact overlapping FDEs, raw records and 27-byte trailing
alignment padding, and binds the next FDE only as a boundary. GNU binutils and
Apple LLVM independently decode all 1,333 bound bytes into 347 matching instruction
partitions. The two selected bodies are 173 bytes/46 instructions; the other
three context callers are 1,160 bytes/301 instructions.

The complete `.text` E8/E9 byte-candidate scan finds three helper E8 sites and
two wrapper E8 sites, each confirmed at an instruction start in a complete
caller FDE. There are zero E9 candidates to either entry. Both other helper
callers load the same bound. The wrapper's only outgoing call is the closed
helper. All 80,300 RELA entries are scanned: none names either entry, overlaps
bound code, or writes any byte of N. N is bound to its exact `.rodata` file
mapping and unique read-only PT_LOAD. See `static/records.json`, complete dual
decodes and `static/frames.txt`. Computed indirect references and unrelated
caller behavior remain unclaimed; no opaque helper is substituted.

## Frozen expectations and native qualification

Before the Rust directory existed, `oracle.py` and exact inputs/expectations were
frozen at `2026-11-01T22:46:21.660452+00:00`. `fixtures/freeze.json` preserves
oracle, raw TSV and deterministic gzip hashes. The oracle uses unbounded integer
comparison, one subtraction modulo `2^256`, and quotient/remainder extraction;
the Rust implementation uses wordwise overflowing subtractions and borrow OR.
Wrapper expectations directly compare A with N and separately test zero.
There is no instruction interpreter, captured execution or post-source supplement.

The 14,449 cases comprise 10,591 general comparisons and 3,858 wrapper inputs,
including all 256 individual bit positions and neighbors, zero/equality, long
borrow chains, high bits, MAX with incoming borrow, N and all bit perturbations,
and deterministic random full-width values. The input-only Rust client receives
no expected data. Qualification with rustc 1.94.1 on macOS arm64 passed:

- Optimization 0 and 3, each independently built twice: 57,796 output rows match
  all 64 bits of all seven observations, with no masks.
- Each optimization's repeated rlib and executable hashes are identical.
- All 32 actually compiled mutant clients exit normally and differ observably,
  including borrow loss/direction, equality, truncated limbs, zero gates,
  RDX/RSI errors and each constant word. Minimum mismatch count is two.
- All 101 static corruption controls reject at the intended structural check,
  including per-instruction changes, caller/FDE/CIE/boundary changes, all 32
  constant bytes, calls/jumps, naming/code relocations and partial constant writer.
- Four comparator corruptions and two archive corruptions reject.

`native/result.json` records exact counts, witnesses, toolchain/source/build
hashes and explicit nonclaims. `native/commands.json` retains every compiler
invocation and output. `native/raw-streams.json.gz` losslessly encodes all 36
exact stdout streams using a shared-line dictionary; each reconstructs to its
original byte count and SHA-256. `verify.py --check-archive` verifies them.
No native build, semantic check or mutant failed. A sandbox DNS fetch failed
and the authorized retry succeeded; `checks/fetch-note.json` records it. A manifest
packaging command initially used the wrong working directory and failed before
writing; `checks/packaging-note.json` retains the correction. Ignored
duplicate raw streams were removed only after exact archive verification with
`work/u256-bound-check/prune-journal.json`; the committed archive retains every byte.

## Reproduction and validation

From the repository root, use a fresh ignored output directory:

```sh
python3 -O research/work-items/RE-001-u256-bound-check-rust-94/verify.py --out work/u256-bound-check-replay
python3 -O research/work-items/RE-001-u256-bound-check-rust-94/verify.py --check-archive
cargo +1.94.1 check --locked --offline --manifest-path src/node94-u256-bound-check/Cargo.toml --all-targets
```

`checks/commands.json` and raw logs record all nine predecessor tests, the exact
legacy packet replay, locked/offline Cargo check, rustfmt and `make doctor`,
`make verify`, `make catalogue-check`, `make reproduce`: all pass. GNU binutils
and rustup paths were prepended to PATH; `checks/tool-versions.json` and native
results identify installed versions. `MANIFEST.sha256` covers this packet,
component and reused parsers/focused predecessor checks; verify from this directory
with `shasum -a 256 -c MANIFEST.sha256`.

No new whole-repository sweep was run. The shared base sweep reported 971 files,
15,462 tests and 69 skips; its aggregate exit 2 arose solely from three disk-full
errors, and all 20 affected tests passed on isolated retry. That is baseline
context, not a clean full sweep at this head. Hosted CI/Linux/container/native
captured-target qualification is not claimed. No pins, generated catalogue,
progress records or completion gates change.

`overlap/` retains exact initial/final read-only inventories: 185 then 187 open
PRs, zero open issues and 50 recent merges in each scan. Neither scope address,
wrapper address nor constant appears in them, and exact source search on current
main has no hit. The existing static packet is the intentional predecessor.
Future work is separately scoped caller reconstruction; this packet makes no
completion claim for those callers or broader modules.
