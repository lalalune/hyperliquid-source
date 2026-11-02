# RE-001: snapshot lane byte reversal with arbitrary data overlap

This adds independent safe `no_std` Rust for the complete node94 function
`[0x56544a0,0x56544f0)`. It closes the Rust gap in
[foundation-half-swap-94](../foundation-half-swap-94/README.md) using the
corrected **four-byte lane reversal** relation, with a proof for arbitrary
source/destination overlap. All 32 source bytes are read before the first
store. The reconstruction also preserves the full incoming RAX value,
without inferring an original source-level return signature.

## Target and boundary

- Component/task: foundation, bounded RE-001 reconstruction. No source
  function/type identity or meaning of the byte fields is claimed.
- Target: node94, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Base: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; reference gitlink
  `999556f6e0a474b8312db96ec3149e1c44e97c23` is unchanged. No inferred
  unlicensed implementation was read or copied.
- Coordinates: linked ELF VAs with section-resolved file offsets.
- New source: [src/node94-lane-byte-reversal](../../../src/node94-lane-byte-reversal/README.md),
  standalone dependency-free Rust 1.94.1, `no_std`, `forbid(unsafe_code)`.
- Author: 신준, with AI assistance; exact model identifier unavailable.
  New code/prose are MIT; retained target bytes preserve their original rights.

The 80-byte body has 22 instructions and one exact overlapping FDE in the
complete 121,299-FDE inventory. Its raw FDE/CIE and every body byte are bound.
GNU and LLVM agree on all instruction boundaries, including the two-byte
`repz ret`. The next FDE begins immediately at `0x56544f0`, so there is zero
padding. That neighboring byte-copy function is excluded; its FDE record is
retained only as a boundary check. Complete `.text` E8/E9 pattern scans find
no incoming candidates; all 80,300 RELA records have no entry-naming addend
or destination overlapping this body. These scans are not a complete
indirect-reference census. There are no calls, conditional branches or
RIP-relative data/global dependencies in this leaf.

`static/` preserves raw dual-decoder exports, exact body/FDE/CIE bytes,
section mappings, complete inventory identity and census results.
[PROOF.md](PROOF.md) derives the byte equation and domain from all instructions.

## State relation and safe API

For byte index i in 0..31, the final destination byte is the **entry** source
byte at `i XOR 3`. Thus `01 02 03 04 05 06 07 08` becomes
`04 03 02 01 08 07 06 05`. Four-byte lanes retain their positions. This is
neither a swap of unchanged halves nor an eight-/32-byte reversal.

The original first loads all four qwords into registers, then performs
eight disjoint dword stores. Consequently the equation holds for exact,
partial and unaligned source/destination overlaps. No byte outside the
32-byte destination changes. No instruction writes RAX, so its complete
incoming bit pattern is preserved. Modified R8..R11 and flags are not
projected.

`reverse_lanes(image, base, source, destination, entry_rax)` uses a single
nonwrapping abstract image with complete nonwrapping 32-byte source and
destination ranges. They may overlap arbitrarily. It validates all ranges,
copies the complete source, converts each four-byte lane from little-endian
u32 to big-endian bytes, and returns `entry_rax`. Missing/nonconforming
ranges return `Err(Unavailable)` with the whole image unchanged. This is a
new safe refusal, not native fault recovery.

Original correspondence requires stable ordinary source data, readable
source/writable destination, valid unchanged code and ordinary return
control disjoint from writable data. The stronger contiguous/nonwrapping
range premise is explicit. Numeric images are not OS mapping promises;
arbitrary wrapped-pointer layouts, MMIO, concurrent changes, faults,
code modification, control-stack writes, physical access traces, flags,
scratch-register outputs and pointer ABI are excluded. The safe return
projects RAX; it does not identify the native source signature.

## Independent frozen expectations and observed qualification

Before Rust existed, `oracle.py` froze **8,553** input/output rows and its
own hash at `2026-11-01T22:04:25.852807+00:00`. Raw and deterministic gzip
hashes are fixed in `fixtures/freeze.json`. It constructs a direct byte-index
patch from the entry image, without bswap, endian conversion, register/flag
instruction interpretation or captured execution. The later Rust uses a
full snapshot and typed endian conversions. The original corpus, oracle
and Rust source did not change during qualification; no supplement was needed.

| Frozen category | Cases |
| --- | ---: |
| Partial overlap | 5,281 |
| Same source/destination range | 495 |
| Disjoint ranges | 1,129 |
| Range unavailable | 1,598 |
| Whole image wraps | 50 |
| Total | 8,553 |

Coverage includes every overlapping byte displacement in both directions,
all 256 input bit bases under seven placements, exact/short boundaries,
high bases, deterministic random images and full-width RAX values. The
client sees only input TSV through stdin and never receives expected
outputs. Its status, full RAX and exact changes over every image byte are
compared without masks.

The first qualification passed **8,553 × four runs = 34,212** observations:
opt0 and opt3, each built and run twice with identical same-level rlib/client
hashes. All **24** compiled mutations exited normally and produced observable
mismatches. They include live-source reads instead of a snapshot, the historical
half-swap rule, full-qword/buffer reversal, alias refusal, writes outside the
destination, writes before a refused destination is admitted and incorrect
RAX values. Equivalent reordering of disjoint stores after a snapshot is
not counted as a mutation kill.

All **31 static**, **four comparator** and **two archive** corruptions reject.
Structural tests below the full-target digest gate cover every instruction,
FDE/CIE, the exact next-FDE boundary, injected E8/E9 edges, naming/code
relocations and an unrelated FDE shifted over the leaf. `native/result.json`
contains witnesses, counts and source/artifact hashes; `native/commands.json`
retains exact compiler commands/results. All **28 exact stdout streams**
are in deterministic `native/raw-streams.json.gz`, encoded losslessly using
a shared line dictionary plus original byte counts and SHA-256 values.
`audit_archive.py` reconstructs each stream and tests deliberate corruptions.

The predecessor's checker uses a Python byte-permutation restatement for
three edge cases; it is not a captured instruction interpreter. The
historically mentioned emulation in its README was neither used nor claimed
as reproducible evidence here. All executed native code was newly authored
Rust on macOS arm64. This is not captured-target differential execution,
x86 machine-code identity, source-level identity or whole-node equivalence.

## Reproduce and limits

From repository root with unchanged materialized LFS inputs:

```sh
export PATH="/opt/homebrew/opt/binutils/bin:/opt/homebrew/opt/rustup/bin:$PATH"
python3 -O research/work-items/RE-001-lane-byte-reversal-rust-94/oracle.py
python3 -O research/work-items/RE-001-lane-byte-reversal-rust-94/verify.py --out work/lane-byte-reversal/replay
python3 -O research/work-items/RE-001-lane-byte-reversal-rust-94/audit_archive.py
python3 tools/foundation_half_swap.py --check research/work-items/foundation-half-swap-94/evidence.json
python3 -m unittest tests.test_foundation_half_swap -v
cargo +1.94.1 check --offline --locked --manifest-path src/node94-lane-byte-reversal/Cargo.toml --target-dir work/lane-byte-reversal/cargo
rustfmt +1.94.1 --check --edition 2024 src/node94-lane-byte-reversal/lib.rs src/node94-lane-byte-reversal/client.rs
make doctor
make verify
make catalogue-check
make reproduce
```

Use a fresh native output directory. Observed tools: Rust 1.94.1, Python
3.14.3, GNU Binutils 2.47.20260726, Apple LLVM 17.0.0, macOS 27.0.1 arm64.
The packet's Python code uses the standard library plus existing repository
ELF/FDE parsers. Exact tool outputs, commands and exit records are in `logs/`.

Prior checker, all **nine focused tests**, Cargo locked/offline, rustfmt,
doctor, verify, catalogue-check and reproduce passed. The separate shared
baseline reported 971 files / 15,462 tests / 69 skips; its original `make test`
exited 2 solely from three disk-full errors, with all 20 affected tests passing
isolated retries. It was not rerun on this head. Skipped Linux tests, hosted
CI, different compiler/host qualification and complete indirect-call coverage
are not claimed.

Live PR/issue/recent-merge snapshots and the source overlap census are
retained in `logs/overlap.json` and `logs/live-inventories.json.gz`. From
this packet directory run `shasum -a 256 -c MANIFEST.sha256` to check packet,
component, parser and predecessor-check/test files. The manifest excludes
itself and Python caches. No imported packet, pin, catalogue or progress
record changes, and no live node, chain action, credential or paid input was
used. Broader acceptance gates remain separate and false.
