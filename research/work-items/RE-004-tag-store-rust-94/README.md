# RE-004: tag-dispatched stores with complete image effects

Component: `foundation`. Target node #94 is the 91,774,280-byte Linux
x86-64 ELF with SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Source base: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.
No inferred reference implementation was read or copied. New code and
documentation are independently authored under the repository MIT license.

The predecessor `foundation-tag-dispatched-store-94` packet established
the static branches but left Rust unimplemented. This reconstructs the
complete `[0x5057700,0x505773d)` leaf with full low32 tag semantics,
runtime load bias, arbitrary overlapping 16-byte copies, exact skipped
accesses, whole-image effects and full RAX=0. All addresses are linked
ELF VAs unless labeled file offsets. [PROOF.md](PROOF.md) states the
full-domain proof and safe API limits.

The selected tag-0 address is formed by LEA; the leaf never reads its
contents. Its actual R_X86_64_64/symbol/version/DT_NEEDED context is bound
as unread metadata, without inventing a runtime symbol-value dependency
or assigning purpose to the surrounding data. Source names and original
ABI/type identity remain unestablished.

## Reproduce

From the repository root with unchanged pinned inputs materialized:

```sh
python3 -B research/work-items/RE-004-tag-store-rust-94/verify_static.py
python3 -O -B research/work-items/RE-004-tag-store-rust-94/verify_static.py
python3 -B research/work-items/RE-004-tag-store-rust-94/verify_rust.py \
  --rustc /path/to/1.94.1-aarch64-apple-darwin/bin/rustc \
  --out work/tag-store-rust/replay
python3 -m unittest discover -s tests -p test_foundation_tag_dispatched_store.py
python3 tools/foundation_tag_dispatched_store.py \
  --check research/work-items/foundation-tag-dispatched-store-94/evidence.json
make doctor
make verify
make catalogue-check
make reproduce
shasum -a 256 -c research/work-items/RE-004-tag-store-rust-94/SHA256SUMS
```

Use a fresh native output directory. Actual rustc 1.94.1 is pinned by
SHA-256 `b69cbcffa5e990057035d53ccc8163e8392ce784f6abb114c19ceb61528ba9f6`
and commit `e408947bfd200af42db322daf0fadfe7e26d3bd1`, with
aarch64-apple-darwin host/target and LLVM 21.1.8. Direct opt0/opt3
builds use edition 2021, warnings denied, one codegen unit, overflow
checks on, explicit `/usr/bin/cc` and recorded path remapping. Exact
commands and compiler/linker executable hashes are retained. There is
no Cargo workspace or dependency resolution.

Static exports use GNU binutils 2.47.20260726, Apple LLVM objdump 17.0.0,
Capstone 5.0.7 and Python 3.14.3. `disassembly.json` records exact commands,
versions, hashes and raw output bindings. Checks include Python `-O`
and different hash-seed/timezone settings; none executes captured code.

## Evidence and comparison

The complete 61-byte FDE has 19 instructions, two returns, four internal
branches and no calls. Full FDE/CIE/neighbor records, internal NOPs,
twelve leading and three following INT3 bytes are bound. The exact LEA
destination `0x57592a0` is anchored to `.data.rel.ro` and PT_LOAD, its
zero file qword and actual relocation/symbol/version records. All 80,300
RELA records and full `.text` E8/E9 candidate scans are checked. No
direct candidate or entry-naming relocation was found; indirect callers
and surrounding table semantics remain unknown.

The [safe library](../../../src/node94-tag-store/lib.rs) admits only
reached source/destination spans in a nonwrapping numeric image. Tag 1
stores the raw source register without dereferencing it; tag 0 stores
the linked address plus load bias; tag 2 takes one complete 16-byte
snapshot before writing. Other low32 tags access neither operand.
Every safe refusal leaves all bytes unchanged. These refusal outcomes
are newly introduced, not a reconstruction of original fault timing.

`oracle.py`, `static.json` and complete input/expected streams were
frozen before the Rust directory existed. The oracle uses integer
modulo tag selection and an immutable positional-byte overlay; Rust
uses a u32 cast, endian conversions, checked ranges and an array
snapshot. The input-only client supplies actual image bytes and observes
full RAX plus every backing byte, including any unused slice suffix.

| Check | Completed result |
|---|---|
| Native opt0/opt3 | 16,756/16,756 exact each |
| Repeated native executions | 16,756/16,756 exact each |
| Raw repeated artifacts | 4/4 rlib/client pairs byte-equal |
| Library units | 3/3 per profile |
| Compiled mutants | 23/23 per profile, 46 total detected |
| Client malformed input | partial/oversized records rejected before output |
| Comparator controls | changed row detected; missing row rejected |
| Static structural corruptions | 30/30 rejected |
| Existing focused suite/checker | 9/9 tests and packet reproduction passed |
| Repository checks | doctor, verify, catalogue-check, reproduce, rustfmt passed |

Nineteen mutants per profile have admitted-value/image witnesses:
wrong tag width/default path, bias/address handling, improper pointer
dereferences, endian/width errors, ordered byte loops, shifted copy
ranges and wrong full RAX. Three per profile test admission only
(eager source, eager destination and strict endpoints). The remaining
partial-output mutant corrupts image bytes before a refusal and tests
the new atomicity guarantee; it is not counted as an admitted native
value counterexample. No source/control correction was needed during
the completed native qualification.

`native-result.json` retains source/tool bindings, all first witnesses
and mismatch counts. `native-commands.json` binds 162 commands to all
324 stdout/stderr streams in `native-streams.json.gz`. Check commands
bind another 18 streams in `check-streams.json.gz`. Both archives are
lossless deterministic base64/deduplicated JSON, gzip compression level
1 with mtime 0. Each command checkpoints its streams before validating
status, so an unexpected failure is retained. Decode each payload and
verify its SHA-256, then resolve stream labels and check command byte
counts/hashes. All bindings were verified after packaging. No native
output or repeated binary normalization is applied.

## Limits and shared baseline

`scope.json` records live open-PR/issue/recent-merge and tracked-source
overlap checks, with the range reserved before implementation.
Existing evidence, pins, registries and generated progress stay unchanged.
This is a host image/value reconstruction, not an original ABI or compiled
target match. Captured binaries and instruction emulators never run.

`shared-baseline.json` is the coordinating worker's separate record:
971 files, 15,462 reported tests and 69 skips. The original `make test`
exited 2 solely for three disk-full errors; all 20 affected tests passed
isolated retry. No successful entire-sweep rerun, full-suite run on this
head, skipped Linux qualification or hosted success is claimed here.

The remaining concrete question is the function's indirect runtime
caller and the selected address's surrounding object role. The complete
leaf relation does not require inventing either missing provenance.
