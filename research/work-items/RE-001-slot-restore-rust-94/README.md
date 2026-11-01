# RE-001: slot restoration with final-tag alias priority

This resolves the Rust gap in `foundation-slot-move-kind-gated-restore-94` for
node #94 ELF VA `[0x3290130,0x3290192)`. The new safe `no_std` image operation
selects one of two slots, updates an adjacent link from a two-hop read, retains
16/8/0 slot bytes by the actual kind bands, and writes output tag 5 last. It
preserves aliases the predecessor's independent slot summary explicitly excluded.
The returned address value represents raw RAX without claiming an original ABI.

Component `foundation`, task RE-001. Target size: 91,774,280 bytes; SHA-256:
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Base: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; reference gitlink:
`999556f6e0a474b8312db96ec3149e1c44e97c23`. Inferred unlicensed implementation
was neither consulted nor copied. New code is independently authored; retained
disassembly keeps the target artifact's original rights. No imported evidence,
pin, generated registry or progress gate changes.

## Proven behavior

[PROOF.md](PROOF.md) derives the full immutable-image relation. The selector is
an entire qword, with zero choosing displacement 16. Kind is an unsigned byte:
0..4 retain 16 bytes, 16..21 retain eight, all others retain none. Every memory
read precedes every store, including the indirect link source. Last-write
priority for the output tag applies even when it aliases that link or slot.
The full kind range is represented; there is no invented enum restriction.

The historical statement that both conditional branches go forward is incorrect:
`ja` at `0x3290189` jumps backward to `0x3290182`, a tag-and-return block, and
cannot loop. This packet corrects the interpretation without editing history.

The safe API uses u64 address values over one mutable byte image. It permits
owner/hop bases below the image if the actual positive-offset field is in range;
only selected state fields are required. It rejects unavailable used ranges and
wrapping addresses before writing. Faults, volatile/MMIO effects, concurrency,
wrapped-pointer behavior and unobserved registers/flags are excluded. A tag
store is a concrete memory effect, not a claim about a source-level variant.

## Static closure

The complete 98-byte body has 26 instructions; GNU and LLVM agree on every
instruction boundary and byte. The 14 outside-FDE padding bytes are separately
bound. All 121,299 FDEs/three CIEs are parsed: exactly one FDE overlaps the body,
and its raw bytes and used CIE are pinned. No call or branch leaves the leaf;
there are no calls or RIP-relative static-data operands in it.

The complete 70,370,352-byte `.text` E8/rel32 scan returns zero direct calls.
No caller FDE is invented. The 80,300-entry RELA inventory has exactly 30
addends equal to this entry, each type 8 with symbol zero. All 30 corresponding
`.data.rel.ro` locations contain eight raw zero bytes; their mappings, locations,
relocation expressions and exact records are retained in `static/records.json`.
These slots relocate to `load_bias+0x3290130`; their owners and actual indirect
consumers remain unknown. Direct-pattern and addend scans are not a complete
xref census. No callback type, vtable identity or wider family is inferred.

## Independent oracle and execution

`oracle.py` extracts entry fields, classifies kind with disjoint mathematical
sets, and constructs final memory pointwise with tag priority. It does not
simulate zero/restore instruction ordering or execute captured code. The input
and expectation freeze requires the source directory to be absent. A pre-source
fixture review added minimal-state cases before the final freeze; its earlier
hash/count and reason are retained in `logs/pre-rust-freeze-refinement.log`.
No implementation or native output existed when that refinement was made.

The final 7,695 frozen cases cover every kind, both selections, all link/slot
positions for tag aliases, aliased hop reads, low-byte-zero nonzero selectors,
exact buffer ends, missing ranges, high address mappings, base-before-image
accesses and deterministic random images. The native client receives only
inputs, emits status/raw RAX and lossless image differences, and never reads
expectations. Omitted difference bytes must match the input exactly; there is
no mask or target-native differential claim.

Validation and replay details follow below.

## Results

- 7,695 cases × four native runs (opt0/opt3, two builds each): 30,780 exact
  comparisons, zero mismatches. Repeated rlib and executable hashes agree at
  each optimization level.
- All 26 compiled mutants exit normally and produce observable differences.
  Late tag priority fails in 5,036 cases, late hop snapshots in 1,672, late slot
  snapshots in 1,441, signed kind comparison in 2,979 and the old scout's
  all-nonfull-half rule in 5,998. Requiring the hop base itself to be mapped
  wrongly rejects 2,760 cases; requiring a whole 81-byte state rejects nine.
- All 92 static controls reject, including each body instruction, FDE range,
  CIE, padding, added E8/naming edges, all 30 relocation addends and all 30 raw
  destination slots. Except the dedicated whole-target corruption, these run
  below the whole-target hash gate. Four comparator controls and two archive
  corruption controls also reject.
- Predecessor checker and eight focused tests pass. `make doctor verify
  catalogue-check reproduce`, offline locked Cargo check, rustfmt, frozen-oracle
  replay and archive reconstruction pass. No full-suite run or parent-run result
  is claimed here.

`native/result.json` retains exact source/compiler/platform/build hashes,
all mutant witnesses and compared fields. `native/commands.json` records every
build invocation and compiler output. One deterministic 2,323,648-byte gzip JSON
archive retains all 30 exact stdout streams through a shared full-line dictionary
and per-stream index lists. Original names, byte counts and SHA-256 are retained;
`--check-archive` reconstructs and verifies all bytes, including newlines.
Changing dictionary bytes or stream order is rejected by the hash check.

The native verifier passed in its first run. The only pre-source refinement was
the documented fixture expansion; no source, oracle or expectation changed after
that final freeze/source implementation sequence.

## Replay

Run from the repository root with installed Rust 1.94.1, Python 3 and GNU/LLVM
objdump. The native verifier needs a fresh ignored output directory:

```sh
python3 -O research/work-items/RE-001-slot-restore-rust-94/oracle.py
python3 -O research/work-items/RE-001-slot-restore-rust-94/verify.py --out work/slot-restore-replay
python3 -O research/work-items/RE-001-slot-restore-rust-94/verify.py --check-archive
python3 -O tools/foundation_slot_move_kind_gated_restore.py --check research/work-items/foundation-slot-move-kind-gated-restore-94/evidence.json
python3 -m unittest tests.test_foundation_slot_move_kind_gated_restore -v
PATH=/opt/homebrew/opt/binutils/bin:/opt/homebrew/opt/rustup/bin:$PATH make doctor verify catalogue-check reproduce
PATH=/opt/homebrew/opt/rustup/bin:$PATH cargo check --offline --locked --manifest-path src/node94-slot-restore/Cargo.toml
(cd research/work-items/RE-001-slot-restore-rust-94 && shasum -a 256 -c MANIFEST.sha256)
```

`GNU_OBJDUMP`, `LLVM_OBJDUMP` and verifier `--rustc` override local tool paths.
`COMMANDS.md` records collection/build chronology. `--freeze` intentionally
refuses with the source directory present; normal oracle replay regenerates and
compares the exact immutable fixture bytes. `MANIFEST.sha256` covers packet,
source, reused ELF/FDE parsers and predecessor checker/test.

## Selection and limits

Initial and final live inventories in `overlap.json` contain 100 and 106 open
PRs respectively, 30 recent merges each and zero open issues. No competing
address/semantic claim was found. Existing qword-search PR #1421 was excluded,
as were parent reservations `0x32d8310`, `0x5632d90` and `0x51a5d60`.
The historical static slot packet is acknowledged and remains unchanged.

This establishes a bounded safe reconstruction and final ordinary-memory
relation. Actual callers, indirect consumers, record/type identities, original
ABI and whole-node integration remain unknown. No captured execution, instruction
emulation, code transplant, native target differential, normalization mask or
progress-gate completion is claimed.
