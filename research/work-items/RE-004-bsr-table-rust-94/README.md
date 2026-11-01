# RE-004: node94 highest-bit table lookup in Rust

The prior `foundation-bsr-lookup-94` packet left this helper's Rust
implementation open. This reconstructs complete node94 ELF VA
`[0x55442e0,0x554431b)`, 59 bytes/17 instructions, as a safe dependency-free
`no_std` library. Target SHA-256 is
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
(91,774,280 bytes); base is `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`,
reference gitlink `999556f6e0a474b8312db96ec3149e1c44e97c23`.

`lookup(value, &[u64;128])` returns zero for zero value, otherwise the
table entry selected by the highest set bit of the packed u128 value.
The [proof](PROOF.md) establishes the original high-word priority, low/high
field packing, guarded BSR, exact 128-word table extent and full-width return.
All value/table bit patterns are admitted. Original objects require stable
ordinary memory; the safe snapshots strengthen availability to both fields
and every table entry. Faults, partial mapping, concurrent changes, original
ABI and table meaning are outside the numeric correspondence.

## Static closure

The leaf body SHA-256 is
`636e62da49cbb941704263572695304cdd9cf28625a9f5dc614403fc2631d95d`.
Complete caller `[0x5522780,0x5522d66)` contains 1,510 bytes and 325
instructions, SHA-256
`0d6c542dce68f00fd933b5810848f94636ffcd645a5d85bf9a0e6d13b73ca657`.
GNU objdump, Apple LLVM objdump and Capstone agree on all body bytes and
instruction boundaries with no prefix/operand normalization. Full FDE parsing
establishes exact unique extents and retains raw FDE/CIE records. Five trailing
INT3 bytes are separate padding. A whole-text E8 scan finds the one site at
`0x5522959`, confirmed within the fully decoded caller. All 80,300 RELA records
are checked for naming and writes over protected code; none is found.

Ten deliberate structural corruptions exercise both field displacements,
branch priority, index bias, BSR, table displacement, padding, FDE, CIE and
caller edge. They bypass only full-file authentication and reach actual
downstream guards. The scans do not establish every indirect reference or
caller purpose. The leaf has no helper or constant-table dependency: table
contents are explicit runtime snapshots.

## Independent native validation

Before Rust existed, the oracle froze 11,160 descriptors and expected results.
It finds the unique half-open power interval containing each nonzero u128
value, without BSR, CLZ or bit-length operations. Expected table values come
from an affine expression plus one explicit override. The input-only client
materializes all 128 actual words before calling the library; no expected
value or sparse callback is supplied. The proof covers arbitrary tables;
these finite affine/override cases provide independent corroboration.

All 128 selected indices and zero are covered, with power neighbors, competing
high/low words, full-width entries and selected/unselected overrides. There
are 12 zero cases. All 11,160 rows match in four host builds/runs (opt0/opt3,
each repeated): 44,640 comparisons. Repeated rlib, executable and stdout hashes
match within each optimization. Two unit tests run per profile; incomplete
driver input is rejected before output.

Nine compiled wrong variants exit normally and differ observably: selecting
table[0] for zero (8 rows), reversed rank (8,526), next rank (9,398), previous
rank (8,516), low64-only rank (6,878), missing upper-word bias (8,884), index
truncated to 64 entries (6,628), u32 output truncation (7,863), and constant
first entry (9,388). Two comparator controls detect one changed row and a
missing byte. No crash or failed compilation is counted as a killed mutant.

`native/result.json` binds sources, compiler/linker binaries, artifacts, raw
outputs and first mutant witnesses. `native/commands.json` retains commands,
statuses and stream hashes. `native/streams.json.gz` losslessly archives all
96 stdout/stderr streams with checked hashes and payloads. Independent read-only
review regenerated the entire corpus and recomputed high-first ranks against
fully materialized tables, checked all 128 indices plus zero, and reran static
verification under `-O`; no blocking issue was found.

## Reproduce

From repository root with the pinned artifacts materialized:

```sh
export PATH=/opt/homebrew/opt/binutils/bin:/opt/homebrew/opt/rustup/bin:$PATH
export LLVM_OBJDUMP=/usr/bin/objdump
python3 -O -B research/work-items/RE-004-bsr-table-rust-94/verify_static.py
python3 -O -B research/work-items/RE-004-bsr-table-rust-94/verify_rust.py \
  --out work/bsr-table-review \
  --rustc /Users/shinjun/.rustup/toolchains/1.94.1-aarch64-apple-darwin/bin/rustc
python3 -B -m unittest tests.test_foundation_bsr_lookup -v
rustfmt +1.94.1 --check --edition 2024 src/node94-bsr-table/*.rs
make doctor verify catalogue-check reproduce
(cd research/work-items/RE-004-bsr-table-rust-94 && shasum -a 256 -c MANIFEST.sha256)
```

The native output directory must be fresh. Qualified host: macOS ARM64,
rustc 1.94.1 commit `e408947bfd200af42db322daf0fadfe7e26d3bd1`, LLVM 21.1.8,
actual compiler SHA-256
`b69cbcffa5e990057035d53ccc8163e8392ce784f6abb114c19ceb61528ba9f6`.
Python 3.14.3 runs guards under `-O`; decoder versions are GNU binutils
2.47.20260726, Apple LLVM 17 and Capstone 5.0.7. Exact compiler/export pins
require those tools; other-host results must be separately labeled.

Eleven focused legacy tests, rustfmt, repository checks and manifest pass;
raw check logs and hashes are retained in `repository-checks.json.gz`.
The separate full legacy sweep remains pending. Hosted CI, captured execution,
instruction emulation, original compiled-byte identity and whole-node completion
are unclaimed. No unlicensed inferred implementation was copied. New code/prose
use the root MIT license; captured bytes/disassembly retain artifact rights.
Only this packet and `src/node94-bsr-table/` change; no pins, imports, catalogues
or progress gates change.
