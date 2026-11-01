# RE-001: checked 256-bit subtraction under ordered memory aliases

Component: foundation. Target node94, size 91,774,280, SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`. Main base `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; reference gitlink `999556f6e0a474b8312db96ec3149e1c44e97c23`, unchanged and unread. Author: 신준.

The existing `foundation-checked-subtract-94` packet established the 87-byte leaf's arithmetic under nonoverlapping storage and explicitly left Rust and arbitrary aliases unresolved. This contribution reconstructs the complete leaf `[0x2760a10,0x2760a67)` in `src/node94-checked-subtract/`, preserving its ordered operand reads, unconditional minuend rewrite, success-only output copy, and full 0/1 RAX. This is distinct from the existing wide-subtract at 0x32d8310, whose body and mutation/return contract differ.

## Established relation and API

The target rewrites one minuend qword after each of its first three right-word reads. Later right words can therefore observe those writes under overlap. The top word is also rewritten before either failure branch. A high-word borrow and the extra incoming-borrow case are separately checked; neither check can be dropped. On success, both result halves are snapshotted before stores at output+24 and output+8; a full qword flag is stored at output last on both paths. RAX is exactly that 0/1 flag.

The `no_std`, safe Rust API uses an abstract-address mutable image and a 32-byte overlay to preserve those ordered dependencies while checking capacity before actual writes. It accepts arbitrary byte overlap among operands and output. It requires nonwrapping mapped 32-byte operands and only the used output range: 8 bytes on failure, 40 on success. Safe refusals leave the whole image unchanged. Fixed-range wrap, native faults/timing, MMIO/concurrency, instruction/control aliases and pointer ABI are excluded. The correspondence is final data image plus full RAX, not a physical access trace. No business meaning or source-level type is inferred.

`PROOF.md` proves the whole-prefix arithmetic invariant and the top two-borrow condition. It also explains why “output payload untouched on failure” requires disjointness: unconditional operand/flag stores may alias those bytes. The original packet and its corrections remain unmodified.

## Static closure

Full target authentication precedes section/FDE parsing. All 121,299 FDEs and three CIEs are decoded; the leaf and complete caller each have exactly their bound overlap, with exact used FDE/CIE bytes retained. GNU and Apple LLVM independently agree on 27 leaf and 475 caller instruction boundaries. The complete caller `[0x2760040,0x2760a04)` is 2,500 bytes. Its three calls at 0x2760924, 0x276095c and 0x2760998 are confirmed instruction starts, with argument setup and flag consumers in the retained body.

Nine trailing INT3 padding bytes are separately bound. Complete `.text` E8 scanning finds precisely these three calls. All 80,300 RELA entries are inspected; none names the leaf and none overlaps the protected code intervals. The leaf has no outgoing call, no branch outside its body and no RIP-relative data dependency. Broader caller behavior and indirect-reference enumeration are excluded. The bridge block-step packet explicitly used this leaf without claiming it; its captured-code emulator was neither read nor used.

Static records, complete dual disassembly and frame exports are retained under `static/`. Thirty-nine corruptions reach instruction/caller/FDE/CIE/padding/call-census/relocation checks; only the explicit target-digest corruption uses the full-file gate. No captured executable or instruction emulator ran.

## Frozen oracle and native evidence

The independent pre-Rust oracle computes arbitrary-precision whole-prefix differences from sequentially observed right words. It rewrites mathematical prefixes rather than modeling registers or flags. The Rust uses byte overlays and limb `overflowing_sub` operations. Its expectations were frozen before the Rust directory existed: 9,329 cases; input SHA-256 `5e0ee2bb8d58c0aeac7df9770da90fd4b8fbde0d4f5ecba6d8cd87c7afba061a`, expectation SHA-256 `25b5edf8334ccab0979083399e9e9ba8412a67c0dd09debcbc3837115b8b604e`. No post-Rust supplement or oracle edit was needed.

Coverage includes all 256 bit positions, high-only/extra/covered borrows, operand overlap offsets -31..31, output overlaps, exact operand/output boundaries, output-short failure success distinctions, high image addresses, invalid ranges and seeded synthetic images. Counts by return/refusal/alias class are in `fixtures/freeze.json`.

All 9,329 cases passed in four native runs (opt0 twice, opt3 twice), totaling 37,316 exact status/full-RAX/full-image comparisons. Each optimization reproduced both library and client hashes. All 29 actual compiled mutants exited normally and differed, including entry-snapshot right operands, lost borrows, skipped failure rewrites, late low-half loads and writes before capacity admission. Four comparator controls and two archive controls were rejected. No masks apply. The input-only client never receives expected outputs. Source SHA-256: `bae3506ab15cb35ac2327ddcd1b2d98732cbb7e78573e59447b5151ee8e4d768`.

`native/result.json` contains tool/platform/artifact hashes and each mutant's mismatch count and first witness; `native/commands.json` contains exact compilation. The deterministic lossless archive retains all 33 stdout streams. This is new host Rust versus target-derived mathematical expectations, not captured-native differential execution or compiled-byte equivalence.

## Validation and limits

First native/static qualification passed. Focused predecessor checker and 11 tests, Cargo offline check, rustfmt, doctor, verify, catalogue-check and reproduce passed. Exact commands and logs are in `COMMANDS.md` and `logs/`; global exit codes are retained. The full test sweep was not repeated. No imported evidence, pins, global config, progress or catalogue changed.

Live read-only checks retained 123 initial and 125 final open PRs, 30 recent merges each and zero open issues. No selected-address/semantic overlap or existing Rust implementation was found; shared history/context is distinguished in `overlap/summary.json`.

No whole-node build/equivalence, source identity, original runtime mapping or progress gate is claimed. The broader caller algorithm and meanings of the arithmetic values remain unresolved.
