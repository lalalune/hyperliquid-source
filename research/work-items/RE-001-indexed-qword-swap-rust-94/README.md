# RE-001: indexed qword selection with ordered overlapping stores

This closes the Rust gap in `foundation-indexed-qword-swap-94` for node94 ELF VA
`[0x4fa90a0,0x4fa9109)`. The independent safe `no_std` image API reconstructs
both threshold-selected table fields, full-width modular index scaling, both
entry qword snapshots, second-then-first stores and the original first-address
RAX. It preserves partial qword overlaps and pointer-field/data aliases, rather
than requiring an abstract disjoint swap.

Component `foundation`, task RE-001. Complete target size: 91,774,280 bytes;
SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Base: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; reference gitlink:
`999556f6e0a474b8312db96ec3149e1c44e97c23`. The inferred unlicensed implementation
was neither read nor copied. New implementation/evidence code is independently
authored; raw target disassembly retains original rights. Imported evidence,
pins, generated registries and progress gates are unchanged.

## Relation and domain

[PROOF.md](PROOF.md) derives the complete relation. Each unsigned index selects
the low field at +264 through 31, or the high field at +272 from 32 onward. On
the high path the loaded base is offset by `8*(index-32)` modulo 2^64. The full
index chooses the branch before scaling discards high bits: `2^61+31` uses the
high field with offset -8, not low-field index 31.

Both base fields and both qwords are snapshotted before writes. The first
selected range is written last and has priority wherever the eight-byte ranges
overlap. RAX remains the computed first address even if that store changes its
source table field. No table length, enum, alignment or source-type invariant
is inferred.

The safe API uses abstract u64 address values over one mutable image. Only used
fixed table fields must be available without wrapping; loaded bases may lie
outside the image. Computed address arithmetic retains target modulo-2^64
behavior, followed by checks that both complete qword ranges fit the image.
The image itself and actual byte accesses do not wrap. Refusals perform no
writes. This is additional safe policy, not a native fault/permission/ABI model;
MMIO, concurrency, control aliases and arbitrary invalid pointers are excluded.
Abstract test mappings are not assertions about Linux/x86-64 address availability.

## Static closure

The complete body is 105 bytes/25 instructions, including an unreachable
nine-byte NOP. Seven following INT3 bytes are separately bound. The complete
caller `[0x4fabb90,0x4fac29f)` is 1,807 bytes/436 instructions. GNU and LLVM agree
on every instruction boundary and byte. All 121,299 FDEs/three CIEs are parsed;
exactly one FDE overlaps each claimed window, and exact FDE/used CIE records are
pinned.

The full 70,370,352-byte `.text` E8 scan finds four callsites, all decoded
instruction starts in the retained caller. Concrete setup at `0x4fabc6b` passes
the same table address in both RDI/RDX, different indices, and overwrites RAX
after returning. Other caller purposes, calls and data dependencies are not
reconstructed. The leaf itself has no calls, no branch outside its FDE and no
RIP-relative static-data read.

All 80,300 RELA records are scanned. No addend names this entry, and no supported
relocation destination overlaps the bound code windows. The checker rejects an
injected code relocation. These direct-pattern and relocation scans do not
exclude indirect/computed references or establish original ownership.

## Independent expected results

The pre-Rust oracle computes selected addresses with an arbitrary-precision
polynomial modulo 2^64, then builds the final image pointwise with first-range
priority. It does not replay the native store sequence or emulate instructions.
The source directory was absent when 5,873 input/expectation cases and oracle
source were frozen and hashed.

Cases include all four threshold combinations, threshold edges, high-bit index
aliases, every partial-overlap displacement, identical/disjoint ranges, same
tables, pointer-field/data collisions, byte patterns, minimal selected-field
availability, exact/short buffers, wrap-sized address arithmetic and deterministic
random combinations. The input-only client never reads expectations. It emits
status, full RAX and lossless whole-image differences: omitted bytes must equal
the input. No output mask is applied.

Validation results and replay commands follow below.

## Validation results

- 5,873 cases × four native runs (opt0/opt3, two builds each): 23,492 exact
  comparisons, zero mismatches. Repeated library/executable hashes are identical
  within each optimization level.
- All 25 compiled wrong variants exit normally and differ. Reverse store order
  and bytewise interleaving each fail 3,704 cases; a late second load fails 5,124.
  Truncating indices fails 2,964; replacing modular scale/add with checked
  operations fails 2,140/2,963. Requiring both fields rejects six valid cases.
- 53 static corruptions reject, covering every body instruction, all four calls
  and sixteen argument-setup sites, FDE extents, CIE, padding, extra call/naming
  edges and a code-targeted relocation. Except the identity control, these run
  below the whole-target hash gate. Four comparator and two archive corruptions
  reject as well.
- The predecessor checker/eight focused tests, `make doctor verify
  catalogue-check reproduce`, offline locked Cargo check, rustfmt, frozen oracle
  replay and archive checks pass. No full test sweep or parent's sweep result is
  claimed here.

`native/result.json` contains source/compiler/platform and artifact hashes,
compared fields and every mutant witness. `native/commands.json` records build
commands and compiler output. The deterministic 1,986,616-byte raw-stream archive
retains all 29 exact stdout streams, with original labels, byte counts and hashes.
A shared full-line dictionary reconstructs each stream exactly, including
newlines; no result is recomputed during compression.

The initial validator stopped at a warning in `first-uses-second-index` after
the four correct builds. That mutant and the analogous wrong-table control now
consume deliberately unused parameters without correcting their wrong behavior.
`logs/native-initial-build-failure.log`, the failed mutant source and
`logs/control-correction.log` retain this event. The final successful qualification
is a complete fresh run; product source, oracle, inputs and expectations were
unchanged. No initial partial comparison is used as final evidence.

## Replay

From the repository root, with Rust 1.94.1 and GNU/LLVM objdump installed:

```sh
python3 -O research/work-items/RE-001-indexed-qword-swap-rust-94/oracle.py
python3 -O research/work-items/RE-001-indexed-qword-swap-rust-94/verify.py --out work/indexed-swap-replay
python3 -O research/work-items/RE-001-indexed-qword-swap-rust-94/verify.py --check-archive
python3 -O tools/foundation_indexed_qword_swap.py --check research/work-items/foundation-indexed-qword-swap-94/evidence.json
python3 -m unittest tests.test_foundation_indexed_qword_swap -v
PATH=/opt/homebrew/opt/binutils/bin:/opt/homebrew/opt/rustup/bin:$PATH make doctor verify catalogue-check reproduce
PATH=/opt/homebrew/opt/rustup/bin:$PATH cargo check --offline --locked --manifest-path src/node94-indexed-qword-swap/Cargo.toml
(cd research/work-items/RE-001-indexed-qword-swap-rust-94 && shasum -a 256 -c MANIFEST.sha256)
```

Use a fresh ignored directory for native replay. `GNU_OBJDUMP`, `LLVM_OBJDUMP`
and verifier `--rustc` override local paths. `COMMANDS.md` records chronology
and options. `--freeze` refuses once the component source exists; normal replay
regenerates the exact frozen bytes and verifies hashes. The manifest binds the
packet, source, reused ELF/FDE parsers and predecessor checker/test.

## Overlap and outstanding scope

Initial/final public inventories contain 111/114 open PRs, 30 recent merges each
and zero issues. No competing address/source claim was found. Generic semantic
matches #1455 (monotone array ordering) and #1456 (ordered reverse-copy) concern
different addresses/algorithms. Parent reservations `0x4ea41e0`, `0x54307c0`
and `0x5178be0` are excluded. `overlap.json` retains both inventories.

Actual indirect callers, table identities/bounds, source ABI and whole-node
integration remain unknown. No captured execution, emulator, transplanted code,
normalization mask, compiled target-byte match or progress completion is claimed.
