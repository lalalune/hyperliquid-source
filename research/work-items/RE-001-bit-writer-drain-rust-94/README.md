# RE-001: reconstruct the bounded node #94 bit-writer drain

- Component: foundation; bounded RE-001 byte/FDE/data-flow question.
- Target: node #94, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Main baseline: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.
- Pinned reference gitlink: `999556f6e0a474b8312db96ec3149e1c44e97c23`;
  no inferred reference implementation was opened or copied.
- Scope: complete `[0x5494050,0x54940d8)` body, full FDE inventory, four full
  caller bodies and all 26 direct E8 call sites, fields, relocation census,
  independently authored Rust value/slice projection and frozen comparison.
- The preceding `foundation-bit-writer-drain-94` packet left Rust unimplemented.
  It is historical static context, not an execution oracle. Its files are unchanged.

## Result and scope

`src/node94-bit-writer-drain` is a real, dependency-free standalone `no_std`
crate with safe code only. Its value API covers every i32/u16/u64 input, including
negative and >16 counters and wrapping positions. Its slice API checks the whole
output interval before mutation; rejection preserves state and output. It also
preserves path-dependent raw RAX as an explicit observation. No native struct
layout, source function identity, or source return signature is claimed.

The [proof](PROOF.md) derives the three-way relation and accounts for ordered
loads/stores. In particular the flush path reloads position, high accumulator
byte and output pointer after the first output store. Stable disjoint state
is essential to replacing those reads with a snapshot. Aliases, concurrency,
MMIO and fault behavior are outside the correspondence. The slice refusal policy
is additional behavior, and value-level wrapping is not arbitrary wrapped-pointer
execution. No `0..16` counter invariant is assumed.

## Static evidence

All coordinates are linked ELF VAs. File offsets are resolved through ELF
sections; no global offset or loader rebase is assumed. Full-target authentication
precedes structural analysis. GNU and Apple LLVM disassemblers agree on every
instruction boundary and byte in all five complete bodies:

| Window | Bytes | Instructions | .eh_frame FDE offset | Direct calls to drain |
|---|---:|---:|---|---:|
| `0x5494050..0x54940d8` | 136 | 32 | `0x2bf2a8` | — |
| `0x5489a10..0x548a2ef` | 2,271 | 593 | `0x2beb2c` | 3 |
| `0x548a2f0..0x548a894` | 1,444 | 354 | `0x2beb78` | 3 |
| `0x548a8a0..0x548b03b` | 1,947 | 446 | `0x2bebf8` | 4 |
| `0x548b640..0x548cebc` | 6,268 | 1,537 | `0x2bed68` | 16 |

The leaf body SHA-256 is
`ad48f7422e3db6481708b67438ab68421a5ef21aacf766496ad4c0447cfe9a66`.
The full 3-CIE / 121,299-FDE inventory is decoded, hashed and searched for
intersections; each retained window overlaps exactly its own complete FDE.
The shared CIE and raw FDE records are retained, and independent GNU frame
exports confirm all ranges. Eight trailing `int3` bytes are outside the FDE;
the internal `xchg ax,ax` padding is inside it but unreachable from entry.

The complete 70,370,352-byte `.text` E8-pattern scan finds exactly 26 incoming
sites; complete caller decoding confirms all 26 as instruction boundaries.
This is not a census of indirect calls or tail jumps. No caller purpose or
caller argument invariant is inferred. The leaf makes no calls and reads no
static constants; its data edges are the counter dword +0x1734, accumulator
word +0x1730 (and high byte +0x1731), output pointer +0x10 and position qword
+0x28. All address operands are bound by the complete bytes. All 80,300 RELA
records were scanned; no record names the leaf as addend. That negative result
does not establish provenance or rule out indirect users.

`static/records.json` retains bytes, hashes, offsets, all overlaps and call
bytes. `static/*-gnu.txt`, `static/*-llvm.txt` and `static/frames.txt` are exact
raw exports, without text normalization. `overlap.json` records live public
scope checks and the pinned main/source search: 58 open PRs initially and 61
on recheck, zero open issues, and no matching PR by address or bit-writer/drain
semantics. Prior static work and nearby-distance mentions are acknowledged.

## Independent expectations and native comparison

`oracle.py` was written and frozen before the Rust component existed. It uses
an algebraic byte-count classification, integer quotient/remainder for digits,
modular position arithmetic, and mathematical interval replacement. It neither
imports the earlier Python drain model nor interprets target instructions.
`fixtures/freeze.json` binds the oracle, 9,600 inputs and full expectations.
The input-only client reads stdin values/initial bytes and never opens expected
outputs. The verifier alone compares exact outputs, without masks.

The 9,600 cases cover the signed endpoints, negatives, 7/8 and 15/16/17
boundaries, high positive counts, every low/high byte value on all paths,
exact/insufficient/empty buffers, surrounding buffer bytes, huge positions and
64-bit wrap. They include 3,863 no-output, 4,870 one-byte and 867 two-byte cases;
2,581 negative counters; 3,501 >16 counters; 805 wrapping value projections;
6,525 successful applications and 3,075 rejections. Those counts describe
finite synthetic coverage, not exhaustive enumeration of all scalar inputs.

Final native result: all 9,600 cases agree at opt0 and opt3, each built/run twice
(38,400 comparisons). Library and client artifact hashes match within each
optimization's repeated builds. Each of 20 compiled mutants exits normally and
produces at least one observable mismatch. They perturb signed branching,
16 equality, byte order/selection, logical word shift, counter reset/decrement,
wrapping positions, all RAX paths, output/state stores, rejection atomicity,
exact capacity, no-output bounds and position truncation. Per-mutant counts and
first witnesses are in `native/result.json`; no crashing/noncompiling mutant
is counted. There are 68 static controls and 4 comparator controls. Structural
corruptions bypass only whole-target authentication so body/FDE/CIE/padding,
caller, direct-call-census and relocation checks are actually reached.

The final full verification also passes under Python `-O`; production checks
use explicit exceptions. One initial rustfmt check reported a client-only line
wrap; it was applied, then the entire final native matrix was rerun. Logs keep
both runs and the formatting correction. There were no native mismatches in
either unmutated run. The earlier raw outputs are not presented as final-source
evidence. `native/raw-streams.json.gz` is one deterministic, lossless archive of
all 24 final exact stdout streams, with labels, byte counts and SHA-256 values;
`--check-archive` validates the archive without recomputing native results.

## Reproduce

Working directory: repository root. Materialize the pinned artifacts first.
No target code, service, node, emulator, keys, chains or networked execution is
used. Read-only GitHub scope queries are separate from target validation.
Commands and flags for every native compile are in `native/commands.json`.
Compiler: rustc 1.94.1, aarch64-apple-darwin; Python 3.14.3; full decoder/compiler
versions in `logs/tool-versions.log`. This is macOS ARM64 validation, not Linux
x86-64 target execution, CI, Docker or an ABI comparison.

```sh
export PATH=/opt/homebrew/opt/binutils/bin:/opt/homebrew/opt/rustup/bin:$PATH
python3 -B research/work-items/RE-001-bit-writer-drain-rust-94/oracle.py
python3 -O -B research/work-items/RE-001-bit-writer-drain-rust-94/verify.py \
  --out work/bit-writer-review
python3 -B research/work-items/RE-001-bit-writer-drain-rust-94/verify.py --check-archive
CARGO_TARGET_DIR=work/bit-writer-cargo cargo build --offline --locked --release \
  --manifest-path src/node94-bit-writer-drain/Cargo.toml
python3 -B tools/foundation_bit_writer_drain.py \
  --check research/work-items/foundation-bit-writer-drain-94/evidence.json
python3 -B -m unittest tests.test_foundation_bit_writer_drain -v
make doctor verify catalogue-check reproduce
(cd research/work-items/RE-001-bit-writer-drain-rust-94 && shasum -a 256 -c MANIFEST.sha256)
```

The verifier requires a fresh `--out` directory and installed GNU/LLVM tools;
`GNU_OBJDUMP`, `LLVM_OBJDUMP`, and `--rustc` can select them. Export text may
differ across decoder versions, so exact retained-export equality requires the
recorded versions. `oracle.py --freeze` intentionally refuses after source
creation; ordinary verification regenerates and checks the original freeze.
Repository checks, the original static checker, all 9 focused predecessor tests,
and the standalone offline Cargo build pass. The full repository test suite was
not duplicated in this worker; no full-suite result is claimed here.

## Limits

This resolves one previously unimplemented bounded helper under its stated
memory domain. It does not identify what the bits encode, establish native
reachable-state constraints, reconstruct callers, or close any component gate.
Passing independently derived expectations corroborates the static proof; it
is not captured-target differential execution or whole-ELF equivalence. Imported
evidence, pins, generated progress and every completion gate remain unchanged.
