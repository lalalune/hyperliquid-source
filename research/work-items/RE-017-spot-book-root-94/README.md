# RE-017: spot-book capture and the second app-hash job

Node #94's second low-lane app-hash job serializes each spot book as two ordered lists of price magnitudes and head-following order records, giving a reconstruction the order and fields of this previously opaque hash input.

- Component ID: `abci`, RE-017, bounded state-root input path.
- Target release and full SHA-256: Linux x86-64 node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `e5c9b6436876b2a4a39daef813171f9879317699`; unlicensed reference lead `999556f6e0a474b8312db96ec3149e1c44e97c23`. Reference labels are leads, not evidence or implementation material.
- Claim status: instruction bytes, selected direct destinations, constants, FDE ranges and call-site tables are observations. Names, serialization roles and conclusions combining separate routines are inferences subject to the conditions below. Runtime identity, scheduling and reachability are unresolved.
- Scope included and excluded: the book-to-job capture, both price-tree and slot-list capture routines, the low-lane nested writer and its selected error branches, plus selected corresponding shared-lane writer ranges and result guards. Previously studied builder, constructor, hash closures, generic marker and finish helpers are explicit boundary context, not new owned functions. The original loader and its GOT and call sites, other hash jobs, primary and secondary builders, actual concurrent mutation, node #115 and visor are excluded. This is not the complete begin/action/end-block path.

## Reproduce

From the repository root on Linux x86-64 with CPython 3.12.3, the standard library and the authenticated artifact available:

```sh
python3 tools/artifacts.py verify
python3 tools/abci_spot_book_root94.py --out research/work-items/RE-017-spot-book-root-94
python3 -m unittest tests.test_abci_spot_book_root94
python3 tools/catalogue.py --check
(cd research/work-items/RE-017-spot-book-root-94 && sha256sum -c MANIFEST.sha256)
PYTHONHASHSEED=1 TZ=UTC python3 tools/abci_spot_book_root94.py --out work/spot-book-repro-a
PYTHONHASHSEED=913 TZ=Pacific/Honolulu python3 tools/abci_spot_book_root94.py --out work/spot-book-repro-b
diff -r work/spot-book-repro-a work/spot-book-repro-b
diff -r -x README.md -x MANIFEST.sha256 research/work-items/RE-017-spot-book-root-94 work/spot-book-repro-a
```

Use empty output directories. The 24 generated TSV/JSON files are listed in the manifest, which also covers this README. The generator checks the entire target SHA-256 before parsing or creating output, imports the repository's `tools/elf_index.py` and `tools/fde_extents.py`, excludes NOBITS sections from file mappings, checks fixed instruction patterns, and reads signed branch displacements directly from the ELF. It never invokes another program. The raw paired-body comparison applies no masks. Development used GNU objdump 2.42 only for human inspection of selected address ranges; its textual output is not an input or generated evidence. The input is read-only. Tests mutate private copy-on-write mappings and do not execute the target.

## Evidence

Coordinates are linked ELF virtual addresses (VA); the tables give file offsets separately and all endpoints are exclusive. An FDE is an unwind-described range, not proof of an original source function boundary or of complete coverage. `bodies.tsv` preserves the full raw bytes of the selected FDEs; `windows.tsv` labels previously studied context separately. Branches, transfers, semantic descriptions and exception links are selected sites rather than complete inventories.

### Entry and capture boundaries

The prior [state link](../RE-017-abci-state-link-94/README.md) binds a `state.rs` Location to a loader. The prior [app-hash builder](../RE-009-app-hash-builder-94/README.md) identifies builder `0x2755dc0`, its job row 2 and the row's low closure `0x2818a10` and shared closure `0x4ae7970`. This packet starts at that already identified builder boundary. It does not establish that the state object received by the builder is the object returned by the original loader.

At `0x27561cf..0x2756273`, the builder loads a count at state `+0x3390`, and for nonzero count loads the book array pointer at `+0x3388`. It advances books by `0xd8`, reserves `0x30` bytes per result, passes `book+0x80` and `book` to the prior constructor `0x2397ae0`, and copies its 48-byte result. The prior [book sampler](../RE-006-book-mid-sampler-94/README.md) independently associates the same state-relative array offsets, stride and two tree offsets with spot books; the spot label here is an inference from those compatible observations, not a symbol in the builder. The first and second calls at `0x2397be6` and `0x2397ce7` both target newly selected `0x26b0930`; the second input advances the first tree pointer by `0x18`, i.e. `book+0x98`. Later constructor stores place the first and second captured vector triples in the same order as the side writer reads them. The direct call instructions and signed destinations are in `transfers.tsv`; the older bodies are context only.

The new tree collector consumes an iterator count. It walks the selected tree entries and reads a signed key at node `+0x168 + 8*index`; its `neg` and conditional move at `0x26b0b5b` produce the magnitude bit pattern, including `0x8000000000000000` for signed minimum. For each entry it calls `0x25681d0` with that level's head and the book's slab context, then appends a `0x20`-byte price/vector record. The iterator-invalid and missing-parent branches reach separate diagnostics followed by `ud2`. These are machine observations; the source-level map type is not asserted.

The existing [price-level lifecycle](../RE-006-price-level-lifecycle-94/README.md) separately observes side-zero insertion into `book+0x80` using a negated key, side-nonzero insertion into `book+0x98` using the positive key, tail append, and head/next unlink on cancellation. **Conditional inference:** for the same unchanged, valid book with the established sorted tree and FIFO link invariants, the captured first side is descending in positive price, the second ascending, and each level's orders follow the maintained head-to-next order. Neither object identity across the separate paths nor the time of capture relative to a mutation is established here.

### Slot capture and failure choices

`0x25681d0` tests that the head's low dword is exactly 1, that its index is below the slab entry count, and that the selected slot's low dword is not 2. Otherwise it returns an empty vector. On a valid first slot it requests `0xe0` bytes, enough for four 56-byte records, and then follows each slot's next word and index at `+0x10/+0x18`. A zero next word ends the list. A later out-of-range index or slot discriminator 2 returns the prefix already collected; a nonzero next word is followed even when its value is 2. The selected implementation does not establish behavior for a cyclic list. These guards do not prove that malformed list representations are reachable.

`slot-layout.tsv` binds the following moves from each `0xf8`-stride slot into a captured `0x38`-stride record. Labels are inferred from the independent writer field literals, not from a recovered Rust declaration.

| Captured record member | Slot bytes or address | Record offset | Width |
| --- | --- | --- | --- |
| `resting_sz`, `orig_sz` | `+0xc8..+0xd7` | `+0x00..+0x0f` | 16 bytes |
| `oid` | `+0xd8` | `+0x10` | 8 bytes |
| `core` reference | address of slot `+0x20` | `+0x18` | 8-byte pointer |
| `user` | `+0xe0..+0xf3` | `+0x20..+0x33` | 20 bytes |
| `tif` | `+0xf5` | `+0x34` | 1 byte |
| `is_position_tpsl` | `+0xf4` | `+0x35` | 1 byte |

The `core` operation stores an address into the original slot, not a deep copy of the core fields. Any claim that a later job sees the earlier values requires the slot and its allocation to remain valid and unchanged. The reader's success branch and the allocation/growth sites do not prove that property.

### Nested writer map

| Step | New FDE start | Selected role and next boundary |
| --- | --- | --- |
| Tree and slab capture | `0x26b0930`, `0x25681d0` | Iterate price entries, take magnitudes, collect linked slots. |
| Outer list | `0x1e5d350` | Write a list of captured 48-byte side-map records; direct child `0x1e4fe30`, buffered child `0x1e50d30`. |
| Side-map | `0x1e4fe30`, `0x1e50d30` | Write two side collections in captured order; walk each at 32-byte stride. |
| Price level | `0x1dd94f0`, `0x1e0c5b0` | Write a two-element structure containing the magnitude and an order list. |
| Order | `0x2333470`, `0x23337e0` | Walk 56-byte captured records; emit seven ordered members on the named path. |
| Core and oid | `0x23d36b0`, `0x23d59b0`, `0x2332010`, `0x23328c0`, `0x23d86c0`, `0x23d8d70` | Dispatch the `core` and `oid` fields; the generic wrapper tail-transfers to `0x2332010`, and the buffered wrapper to `0x23328c0`. |
| Selected core field writers | `0x23d41c0`, `0x23d47a0`, `0x23d4c70` | Write selected `R`, `s`, `d` fields and their child values. |
| Shared-lane counterparts | `0x4446250`, `0x4440d60`, `0x443b230`, `0x43c6220` | Corresponding outer, side and level stages; its nonempty order child `0x49e77f0` remains a boundary. |

`extents.tsv` gives the FDE ends and full-range hashes. In the low closure the call at `0x2818a4c` selects the outer writer. The writer sets its options to the checked word `0x01000400` followed by byte 0, and supplies the literal `SideMap`; the named-field option and direct/buffered states have distinct tests. On ordinary direct output, the seven field names appear in this order: `is_position_tpsl`, `resting_sz`, `orig_sz`, `user`, `tif`, `core`, `oid`. The names, literal lengths, record offsets and instruction operands are in `order-fields.tsv`. Position-only and buffered forms must not be assumed byte-identical to that named form.

Both selected `core` writer variants test the following fields in order. Offsets are relative to the pointer in the captured record; `s` and `l` are reached unconditionally on the selected normal path. The generic route's selected literal references and lengths, including short contexts in the `R`, `d` and `b` helper boundaries, are in `core-names.tsv`. Field values, the full nested `R` and `d` helper grammars, and all indirect helper behavior are not completely decoded.

| Field | Selected presence test |
| --- | --- |
| `t` | qword `+0x88` is nonzero |
| `S` | low byte of qword `+0x00` is nonzero |
| `r` | byte `+0x90` is nonzero |
| `R` | `(byte[+0x10] | byte[+0x20] | (qword[+0x40] != 0)) & 1` is nonzero |
| `d` | qword `+0x70` is nonzero |
| `c` | byte `+0x91` is nonzero |
| `b` | low byte of qword `+0x48` is nonzero |
| `s`, `l` | no corresponding optional-presence branch in the selected path |

The header-count arithmetic and field-presence tests coincide in the synthetic canonical 0/1 tag controls. They are not assumed interchangeable for arbitrary noncanonical words or bytes, and no claim is made that such representations are reachable.

On the selected generic normal path, the byte at core `+0xa2` chooses the `s` value by its low bit: clear selects the one-byte string `B`, set selects `A`. The following `l` value comes from the qword at `+0x80`. The literals and both branch edges are checked independently; this observation does not identify the original enum declaration.

### Successful shape and synthetic boundary examples

The previously pinned array-marker routines select a fixed-array base of `0x90` below count 16. The checked direct finishers return the success sentinel without adding a marker when their local word is `0x8000000000000000`. Combining those prior boundary bytes with this packet's fixed call, option and empty-loop bytes gives the following **synthetic predictions**, not target-execution results or captured state:

| Input shape, assuming successful direct writes and valid disjoint buffers | Predicted bytes |
| --- | --- |
| zero books | `90` |
| one book with both sides empty | `91 92 90 90` |
| one book, first side with one price-127 level and an empty order list, second side empty | `91 92 91 92 7f 90 90` |
| same structural control with price 128 | `91 92 91 92 cc 80 90 90` |

The latter two deliberately use an empty order list inside a level as a structural/corruption control; the prior lifecycle removes empty levels, so their presence in a valid live book is not asserted. The 16 empty-book-count shapes and five small-price controls are generated in `empty-examples.tsv` and `empty-level-examples.tsv`; `model-anchors.tsv` records the checked operands. Their predictions assume successful calls, no aliases changing the checked data, and a compatible constructed record. They do not test execution of the captured node.

The earlier app-hash builder evidence identifies the row closure's hash as Keccak-256. `hash-parameters.tsv` records the prior closure's rate and delimiter operands, the 32-byte output length, the prior round loop's RIP-relative table pointer and loop bound, and the 24 table words read from the authenticated ELF. An independently authored Keccak model uses those words and derives its rotation positions arithmetically; for each synthetic empty-book input it predicts a row digest in `empty-example-digests.tsv`. For example, the predicted digest for `90` is `632315f5af09a9a7da25ae16c4f8560df2b48d94d524d354b69f35289c56e0ea`, and for `91929090` it is `059fa9e00a00f3446bde77a696ed362576104466f6a45de5492cdebf4af94507`. The model passes two standard Keccak known-answer checks and, with the SHA-3 delimiter, matches Python's independent SHA3-256 across rate-boundary input lengths. These are conditional calculations for invented inputs, not observed node digests, final app hashes, or proof that a particular node state has either shape.

`one-order-example.tsv` adds a nonempty synthetic input: one first-side level of price 1 with one order, both sizes and oid 1, an all-zero 20-byte user, position flag 0, tif tag 5, no optional core fields, `s = B`, `l = 1`, and an empty second side. Given the selected successful generic named-writer path and the earlier [prefixed-hex helper](../RE-005-prefixed-hex-rust-94/README.md), it predicts a 119-byte input and row digest `ae8c95e2cc30ca52e08d78f7bd9ad95923837da75a6444c61ee8a0ae942dd612`. `order-model-anchors.tsv` binds the selected map, string, boolean, null and hex-length bytes. A separately written minimal reader in the tests checks the predicted nested shape and map key order. This remains a constructed example: the slots, core pointer, absence tags, user and helper success conditions are assumptions, and it is not a target-generated fixture.

### Result and failure propagation

`decisions.tsv` retains 59 selected, labelled branch decisions and `branches.tsv` has 182 selected branch encodings, fallthroughs and destinations. Examples:

| Selected condition | Observed consequence |
| --- | --- |
| Outer count has a nonzero high 32-bit half | Enter the buffered path, rather than infer unconditional rejection. |
| Outer count is zero | Finish without calling the side writer. |
| Array header result differs from 2 | Return its error payload before writing the next child. |
| Side, level or order child differs from `0x8000000000000004` | Enter the corresponding child-failure return path. |
| Buffered count equals `0xffffffff` | Take the selected diagnostic and `ud2` path. |
| Tree iterator flag is clear or a required parent is null | Take separate diagnostic/`ud2` paths. |
| Allocator returns zero | Take the recorded allocation-failure branch. |

Immediately after each prior hash closure calls its new outer writer, `closure-results.tsv` checks the returned word against `0x8000000000000004`. The low branch at `0x2818a66` goes to `0x2818b62` on inequality and otherwise loads the buffer fields; the shared branch at `0x4ae79c6` analogously goes to `0x4ae7ac2`. The earlier builder packet identifies each closure's subsequent hash core. This is conditional static dataflow, not a calculated digest or proof of final state-root equivalence.

`lsda-headers.tsv` and `lsda-rows.tsv` retain 11 selected LSDA tables and 80 encoded call-site rows; `lsda-call-links.tsv` associates 45 selected calls with their return-PC-minus-one lookup, 13 with nonzero landing pads. For example, the tree collector's call at `0x26b0b50` lies in `0x26b0b46..0x26b0b55` with landing `0x26b0be6`, whose bytes save the accumulated length and resume unwinding. Action tables, exception personality, all indirect callees, cleanup effects and rollback remain unresolved.

The four selected low/shared FDE pairs have equal lengths. `twin-differences.tsv` records 75 runs totaling 221 differing raw bytes; no operand is masked. This does not establish semantic equivalence, relocation closure, or identical output for the two lanes.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Build scope, Cargo lock, compiler/linker settings, two-build result, target-generated behavioral fixtures, reconstruction-to-target byte comparisons and masks, helper closure, vtable/data/relocation closure and whole-ELF comparison: **not yet measured**. The model cases are derived predictions with synthetic inputs, not executions or target comparisons. The captured node and visor were not executed.

## Results and limitations

`summary.json` records 22 selected FDE ranges totaling 22,067 bytes, 57 byte windows including 13 prior contexts, 182 selected conditional branches, 52 selected relative transfers, 13 extracted immediate predicates, 7 order-field rows, 11 generic core name/value literals, 7 slot-layout rows, 2 closure result guards, 25 model anchors, 16 empty-book cases and predicted row digests, 5 empty-level controls, and one complete synthetic one-order case. These are selected packet counts, not a denominator for ABCI or a function-coverage claim. The focused 33-test suite passes without skips; it corrupts hashes, FDE ranges, file mappings, selected branches and calls, literals, layout instructions, result guards, model and hash anchors, the round table and LSDA records, and checks arithmetic and malformed-link controls. Two independently generated sets match under different hash seeds and time zones with binutils unavailable to the generator. Artifact verification and catalogue checking pass; the repository-wide suite was not run under the stated memory constraint.

No ABCI progress gate is requested; the component remains 0/4. This packet does not close the original loader-to-builder object identity, prove live ordering or nonaliasing, reconstruct all 41 job inputs, decode every named value, establish all success or failure paths, or cover full begin-block, action, end-block and state-root behavior. **Next question:** can an unowned handoff prove that the successfully loaded object supplies the low builder, and that the book slots referenced by its captured records stay alive and unchanged until their hash job completes?
