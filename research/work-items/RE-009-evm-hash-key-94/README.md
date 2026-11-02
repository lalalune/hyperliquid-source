# RE-009: the first operand of a nonempty EVM snapshot hash row

A selected nonempty `block_hashes` row writes a two-item compact array with two 32-byte operands: the first payload reverses its memory bytes and the second preserves theirs, and selected reader arms invert those rules while checking lengths.

- Component ID: RE-009, storage and state snapshots.
- Target release and full SHA-256: Linux x86-64 node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663` / `999556f6e0a474b8312db96ec3149e1c44e97c23`. The unlicensed reference is a lead only; no source is copied.
- Claim status: observation for the pinned instructions, calls, branch destinations, literals and unwind records; inference for the row-operand interpretation and compact encoding; unresolved for the original type, file mode and unselected row grammar.
- Scope included and excluded: the two operands' selected serializer and reader paths, 32-byte transform, compact headers and relevant selected failure exits. The previously studied row writer is used only for two contextual call sites and argument setup. Other reader modes, collection ordering, complete file grammar, execution and other releases are excluded.

## Reproduce

From the repository root with Python 3.12.3 and the repository's shared ELF and FDE parsers:

```sh
python3 tools/evm_hash_key94.py --out <tmp-dir>
cmp <tmp-dir>/evidence.json research/work-items/RE-009-evm-hash-key-94/evidence.json
python3 -m unittest tests.test_evm_hash_key94
(cd research/work-items/RE-009-evm-hash-key-94 && sha256sum -c MANIFEST.sha256)
```

The extractor verifies the entire target digest before parsing; it reads the bytes, section table and FDEs without executing the capture. It checks selected full-body hashes, exact SIMD bytes and significant-byte scan shape. It emits deterministic JSON with raw byte windows and decoded direct-call and conditional-branch destinations. It invokes no external program. GNU objdump 2.42 was used only for manual interpretation of bounded windows, not as generator input. No network, key, database, or node execution is involved.

## Evidence

All addresses are unrelocated ELF virtual addresses; FDE ends in the JSON are exclusive. File offsets and FDE addresses are also recorded there. An FDE is an unwind-described extent, not proof of all function boundaries or cold parts. The two calls from the earlier row writer are contextual, not newly analysed whole functions. The earlier `RE-009-evm-state-wire-94` packet links its nonempty collection loop to that row writer and documents the enclosing field; this packet starts at its first-operand callees.

| Selected extent | Role established by selected bytes |
| --- | --- |
| `0x28fa6f0..0x28fabf6` | first serializer variant, mode byte at `+0xa` |
| `0x28f8430..0x28f89ac` | alternate serializer variant, mode byte at `+0x1a` |
| `0x28f7810..0x28f78d6` | 32-byte allocation and SIMD transform |
| `0x25aa380..0x25aa48c`, `0x25aa000..0x25aa37e` | compact header and copy in the first variant |
| `0x25a9ea0..0x25a9ffd` | alternate compact header writer |
| `0x28fb0c0..0x28fb495`, `0x21b7410..0x21b7473` | formatting preflight and selected hex-digit formatter |
| `0x269fcb0..0x269febf`, `0x17e8e70..0x17e993b` | collection reader loop and selected row reader |
| `0x18af3f0..0x18afc80` | first-operand reader, selected binary-length arm |
| `0x2805530..0x280565b`, `0x28068f0..0x2806af2` | second-operand writers, selected compact and text modes |
| `0x17fe9c0..0x17ff200` | second-operand reader, selected binary-length arm |

The row writer saves its first operand from `rdx` into `rbp`, and passes that pointer to the two serializer variants at `0x1de3681` and `0x1de36f0`; those calls are alternatives within previously recorded context. This is evidence about the pointer used by this row, not a recovered Rust type. The reference's proposed `u64` mapping is not established for this operand by these observations.

| Variant and condition | Observed path | Result or next action |
| --- | --- | --- |
| First, mode byte zero | `0x28fa708` to `0x28fa725` | call `0x28f7810`, then `0x25aa380` with its buffer and length |
| Second, mode byte zero | `0x28f8448` to `0x28f8469` | call `0x28f7810`, then `0x25a9ea0` and copy the returned buffer |
| First, mode byte nonzero, all 32 bytes zero | 32 descending byte tests, `0x28fab52` zero arm | pass the three literal bytes `0x0` to a string writer |
| First, mode byte nonzero, some byte nonzero | highest nonzero byte then reverse walk toward offset zero | format a string and pass it to the string writer |
| Second, mode byte nonzero, all zero | zero arm at `0x28f890f` | pass the same three literal bytes to its string writer |

The first transform loads two 16-byte halves from the operand and applies unpack, dword and word shuffle, and saturating pack instructions. The extractor checks the complete fixed byte pattern and symbolically evaluates those lane operations: output positions select input indices 31 down to 0. Its 32 one-hot tests additionally distinguish every lane. The helper allocates `0x20` bytes and returns that length; an allocation-null branch at `0x28f7828` goes to the failure call at `0x28f78c6`.

For the compact path, the byte-header selector chooses `0xc4` for length `0x20`, and the marker combiner's pinned entry returns that value unchanged. The two byte writers use the returned 32-byte reversed buffer. Conditional on success, a standalone operand therefore has `c4 20` followed by the reversed 32 bytes. `evidence.json` contains six static examples, including an asymmetric ascending input; these are models derived from the pinned bytes, not captured node output. The alternate writer has a separate buffer-capacity branch (`0x28f84a6`) and header-error return (`0x28f8496`). The first writer propagates a non-success header result (`0x25aa3ac`), tests arithmetic carry during growth (`0x25aa3d5`), and returns a non-success result when its child result differs from 2 (`0x28fa752`). The text paths have separate formatting and allocation failures. Exact complete error values and unwinding effects are not claimed.

The reader side supplies an independent check. The previously mapped outer reader calls the collection loop at `0x1a0155a`; the loop calls the row reader at `0x269fd15`. Given the row reader's sequence route, a nonzero element count, and its selector byte `+0x24` equal to zero, it calls the first-operand reader at `0x17e93ce` with `edx = 1`. A count of zero reaches the first-element error (`0x17e9398`); after a successful first element, a count of one reaches the second-element error (`0x17e9421`). An insertion helper returning 1 reaches the literal `duplicate key` error construction in the collection loop; this does not establish every duplicate policy on other reader routes.

For the selected first-operand reader arm, an entry state byte of 1 fetches a marker from the input at `0x18af5de`. Marker `0xc4` follows the range tests and the raw-marker table at `0x3232e4` to `0x18af4bb`, which reads one length byte. The alternative pre-decoded state table at `0x322f18` maps selector `0xc4` to the same length-read block at `0x18af4b3`. After the length is subtracted from remaining input, underflow branches to `0x18af736`; on the `edx = 1` path, length unequal to 32 branches to `0x18afbc5`. A length of 32 loads four 64-bit words from input offsets 24, 16, 8 and 0, byte-swaps each, and stores them in that order at output offsets 8, 16, 24 and 32. Thus the 32-byte output payload is the reverse of the selected input payload, the inverse of the writer transform. The tests exercise a static conditional round trip and truncated and wrong-length controls. The static round trip assumes reader state byte 1 and the observed binary-mode argument; the code that initializes the state for a complete snapshot remains outside scope, so this is not a claim that every complete modelled row is accepted.

The second operand takes a different byte-order path. The already mapped row writer calls `0x28068f0` at `0x1de3986` or `0x2805530` at `0x1de3aa0`. In the former's mode-zero, available-capacity path, it emits the `0xc4` marker and byte `0x20`, then copies the two 16-byte halves from the operand without shuffling. The latter passes the unmodified pointer and length 32 to the previously examined compact byte writer. In the nonzero mode the scalar branch formats all 32 bytes in input order with two lowercase hex digits per byte, prepending `0x`; the SIMD formatter's full behavior is not independently evaluated here. The two writer variants propagate the selected non-success results and have separate capacity and format paths, whose raw windows are retained.

The row reader calls `0x17fe9c0` for the second element after its first child succeeds. On its selected binary branch, insufficient remaining payload branches to `0x17fec99` and length other than 32 branches to `0x17ff044`; a length of 32 copies both 16-byte halves in order to the output. Conditional on the row writer's direct array-header path, both mode bytes being zero, successful allocation and sufficient buffer capacity, the complete row model is `92 c4 20 <first operand reversed> c4 20 <second operand unchanged>`. The asymmetric 69-byte example in the JSON is generated from synthetic operands, never a captured node fixture. The row reader's selected children establish the corresponding operand transformations; full stream initialization and alternate error precedence remain unproven.

On the first text path the extractor locates all 32 descending zero comparisons from offsets 31 through 0, including the final zero literal. The selected formatter uses the ELF digit table `0123456789abcdef`; formatting templates and all formatter settings have not been completely interpreted. In particular this packet does not claim a complete text representation for nonzero values.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Build, source comparison, masks, helper closure, target execution and on-disk fixtures are **not yet measured**. The tests include a wrong digest, a code mutation with recomputed digest, altered call and SIMD bytes, a rehashed reader-table corruption, an unmapped address, a NOBITS section, wrong operand lengths, all 32 one-hot lanes, asymmetric expected bytes, a complete conditional 69-byte row model, and conditional reader round-trip and length controls. These controls validate the extractor and its bounded model; they are not evidence of runtime equivalence.

## Results and limitations

The extractor records 14 selected FDE extents, 43 bounded windows, 22 direct calls, 55 conditional branches and 32 significant-byte tests. Eleven focused test methods passed. These are selected evidence counts, not a component denominator. No milestone gate is requested. The exact semantic types and ownership of both operands, first operand nonzero text formatting, other reader paths and error precedence, and whether this mode is used in a particular checkpoint remain open. The next question is to trace outer reader-state initialization and the collection ordering, then validate a complete nonempty row fixture in an authorized offline harness.
