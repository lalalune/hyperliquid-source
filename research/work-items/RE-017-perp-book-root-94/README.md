# RE-017: materialized DEX books and state-root job row 1

Node #94's state materializer copies an input vector triple at `+0x1848` to output `+0x3368`, where state-root job row 1 (zero-based) reads the pointer and length for a DEX-by-book collection; its capture and writers now specify the nested order and failure choices needed to reconstruct that hash input.

- Component ID: `abci`; RE-017 state loader and app-hash job row 1 (zero-based).
- Target release and full SHA-256: Linux x86-64 node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: `e5c9b6436876b2a4a39daef813171f9879317699`; unlicensed reference lead `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference is a lead only and no reference code is copied.
- Claim status: the checked bytes, operands, relative destinations, FDE bounds and relocations are observations. Roles, field names and combinations of independently studied paths are inferences. Actual object identity, scheduling, reachability and full block semantics remain unresolved.
- Scope included and excluded: newly selected capture, nested serializer and shared order-writer ranges; two small materializer context windows; previously identified job descriptors and their contextual handoffs; selected branch and unwind evidence. The earlier loader GOT, original loader call sites, old materializer function, common low-order collectors and generic primitive helpers are boundaries, not newly owned functions. Node #115, visor, target execution and a complete begin/action/end-block path are excluded.

## Reproduce

From the repository root on Linux x86-64 with CPython 3.12.3, the standard library and the authenticated artifact available, replace `<tmp-dir>` with a writable directory whose `first` and `second` children do not yet exist:

```sh
python3 tools/artifacts.py verify
PYTHONHASHSEED=1 TZ=UTC python3 tools/abci_perp_book_root94.py --out <tmp-dir>/first
PYTHONHASHSEED=913 TZ=Pacific/Honolulu python3 tools/abci_perp_book_root94.py --out <tmp-dir>/second
diff -r <tmp-dir>/first <tmp-dir>/second
diff -r -x README.md -x MANIFEST.sha256 <tmp-dir>/first research/work-items/RE-017-perp-book-root-94
python3 -m unittest tests.test_abci_perp_book_root94
python3 tools/catalogue.py --check
(cd research/work-items/RE-017-perp-book-root-94 && sha256sum -c MANIFEST.sha256)
```

The generator checks the entire target digest before making output, imports `tools/elf_index.py` and `tools/fde_extents.py`, rejects NOBITS for VA-to-file mappings and reads fixed instruction forms and relocations directly. It invokes no external program. GNU objdump 2.42 was used only for human inspection; none of its output feeds generated records or tests. The target is opened read-only; corruption controls use private copy-on-write mappings. `MANIFEST.sha256` covers this README and all generated files in this directory.

## Evidence

All addresses are linked ELF virtual addresses (VA), not runtime addresses. Files carry their own file offsets; range ends are exclusive. An FDE is an unwind-described range, not proof of a source function boundary. `fdes.tsv` contains complete unmasked bytes of the 26 selected ranges. `windows.tsv` distinguishes those selected bytes from `prior_context`, and the listed branches and transfers are selected sites, not an instruction census.

### From the loader boundary to the DEX collection

Earlier [state-link evidence](../RE-017-abci-state-link-94/EVIDENCE.md) identifies the `state.rs` Location, the loader's result-tag branch and its non-tag-2 call into the separately studied [materializer](../RE-016-state-chain-94/EVIDENCE.md). The old call sites and GOT are not republished here. The earlier evidence also describes the input block copying and output buffer convention. On that non-tag-2 route, the two newly interpreted context windows at `0x3751ed6` and `0x375224e` show the materializer taking a pointer to input `+0x1848`, saving it, and copying three words to output `+0x3368..+0x337f`. The saved stack slot and the output register must retain their values across the intervening calls; normal ABI preservation and nonaliasing are assumptions of this dataflow interpretation.

| Materializer input | Materializer output | Builder observation |
| --- | --- | --- |
| `+0x1848` | `+0x3368` | first vector word; original type not established |
| `+0x1850` | `+0x3370` | pointer loaded by the low builder |
| `+0x1858` | `+0x3378` | count loaded by the low builder |

`materializer-crosswalk.tsv` derives these offsets from the checked immediate bytes. The preceding loader evidence identifies the materializer input with a copy of the parser result on the selected path. The [app-hash builder](../RE-009-app-hash-builder-94/README.md) separately identifies the row-1 builder, closure and digest work. Matching offsets do not establish that a particular result of the loader is later the same live object passed to that builder.

The low builder loads `+0x3370/+0x3378` and iterates `0x138`-byte entries. Within each, the book array pointer and count are at `+0x08/+0x10`, with `0xd8`-byte books. In the prior primary and secondary builder contexts, the shared capture is called using arrays at `+0x3df0/+0x3df8` and `+0x3370/+0x3378` respectively. `layouts.tsv`, `windows.tsv` and `transfers.tsv` retain the actual operands and fixed relative calls. The DEX and perp names are inferred from the compatible [book sampler](../RE-006-book-mid-sampler-94/README.md) and the earlier builder's registry check.

### Capture and nested writer map

| Stage | Selected FDE start(s) | Selected observation |
| --- | --- | --- |
| Low price-level capture | `0x26b35b0` | Existing constructor calls it once per side; it builds `0x20`-byte level records and calls the previously studied slot collector. |
| Shared capture | `0x4878b00`, `0x4a07530`, `0x487a9f0` | Walk books at `0xd8`, make a `0x30`-byte two-side result, and capture levels and their linked orders. |
| Outer DEX array | `0x1e5ce30`, `0x4446870` | Consume `0x18`-byte vector triples and call the corresponding book-list writer. |
| Books within each DEX | `0x1ddb120`, `0x43c6690` | Walk `0x30`-byte side-map records in input order. |
| Two sides | `0x1e57450`, `0x1e4d020`, `0x4439910`, `0x4442100` | Write two side collections and walk each level at `0x20` stride. |
| Price and orders | `0x1dfc1f0`, `0x1e093c0`, `0x43dee00`, `0x43ebe70` | Write a pair containing a price value and an order collection at `0x38` stride. |
| Shared buffered order and fields | `0x49e7b60`, `0x4abb100`, `0x49e6da0`, `0x4abb600`, `0x4aba330`, `0x4abb380`, `0x4abc300`, `0x44356c0`, `0x45a6a50`, `0x4abb070` | Write the seven selected members, nested `core`, and selected null, address and oid paths. |

The prior low constructor's calls at `0x23976f6` and `0x23977f7` both reach the new low collector. The shared builder calls `0x4878b00`, which calls `0x4a07530`, which calls `0x487a9f0` for each side. On both selected collector paths the `neg`/conditional-move sequence emits the key's magnitude bits; the signed minimum retains bit pattern `0x8000000000000000`. The low collector delegates its order slots to the previous spot-book packet's `0x25681d0`; this packet instead owns the separate shared inlined slot capture.

The separately studied [price-level lifecycle](../RE-006-price-level-lifecycle-94/README.md) places side-zero entries in the tree at book `+0x80`, side-nonzero entries at `+0x98`, and maintains head-to-next links on insert and removal. If those mutations and this capture operate on the same valid unchanged book, they support descending bid-shaped prices, ascending ask-shaped prices and head-to-next order within a level. This is a conditional connection, not proof of object identity, synchronization, or a complete action mutation path.

### Shared slot capture and order fields

For each head, `0x487a9f0` checks discriminator 1, checks the index against the slab count and rejects slot discriminator 2. A failed head check produces an empty order vector for that level. For a valid head it initially requests `0xe0` bytes, enough for four `0x38`-byte records. A zero next word terminates; an out-of-range next index or a slot tagged 2 terminates with the prefix already captured. A nonzero next word is followed without requiring it to equal 1. The synthetic prefix model rejects cycles to terminate its own tests; the target's behavior for a cyclic representation is not established. No malformed live state is asserted.

`slot-copies.tsv` pins source and destination instruction bytes separately. Slot stride is `0xf8`:

| Inferred member | Slot source | Captured record offset |
| --- | --- | --- |
| `resting_sz`, `orig_sz` | 16 bytes at `+0xc8` | `+0x00` |
| `oid` | word at `+0xd8` | `+0x10` |
| `core` | address of `+0x20` | `+0x18` |
| `user` | 20 bytes at `+0xe0` | `+0x20` |
| `tif` | byte at `+0xf5` | `+0x34` |
| `is_position_tpsl` | byte at `+0xf4` | `+0x35` |

The core field is a pointer into the original slot, not a deep copy. The backing allocation and contents must remain valid and unchanged until the later writer reads them; this packet does not establish that lifetime or rule out concurrent mutation.

The shared buffered writer reads the record in the order `is_position_tpsl`, `resting_sz`, `orig_sz`, `user`, `tif`, `core`, `oid`; the key bytes and record offsets are independently checked in `field-literals.tsv` and `order-fields.tsv`. For the selected canonical mode bytes, mode 1 writes a seven-entry map header `0x87`, while mode 0 writes a seven-element array header `0x97`. `header-cases.tsv` records the machine arithmetic for all 256 synthetic byte values without asserting that noncanonical modes occur. Tif tag 5 selects `0x44356c0`, whose selected path writes `0xc0`; other tags go to a separate boundary helper. The user helper supplies an input length of 20 and output buffer length of 42 to the previously studied prefixed-hex primitive; its result then goes to a string writer. Oid is passed to the selected `0x4abb070` wrapper and then to the existing unsigned writer.

The nested shared core checks `t`, `S`, `r`, `R`, `d`, `c`, `b`, followed by unconditional `s` and `l`. The conditions are, respectively, nonzero qword at `+0x88`, nonzero low byte of qword `+0x00`, nonzero byte `+0x90`, `(byte[+0x10] | byte[+0x20] | (qword[+0x40] != 0)) & 1`, nonzero qword `+0x70`, nonzero byte `+0x91`, and nonzero low byte of qword `+0x48`. The `s` value uses the low bit of byte `+0xa2`: clear writes `B`, set writes `A`. `core-count-cases.tsv` separates the observed count arithmetic from these presence tests, including synthetic noncanonical controls; equivalence is only claimed for the tested canonical flags.

### Result and failure choices

`decisions.tsv` labels 26 selected conditions, with raw instructions, taken and fallthrough VAs; `branches.tsv` retains 360 selected branch encodings. Examples:

| Condition | Selected consequence |
| --- | --- |
| Low iterator flag clear or required parent null | Separate diagnostic paths reach `ud2`. |
| Shared head tag, index or slot check fails | Emit the level with an empty order vector. |
| Later linked slot is out of range or tagged 2 | Stop and keep the already captured prefix. |
| Shared first-record allocation returns null | Take the allocation-failure path ending at `ud2`. |
| Outer array count has nonzero high 32 bits | Enter the buffered path. |
| Array header result is not 2 | Return its error payload. |
| Nested writer result differs from `0x8000000000000004` | Copy the child result to the output; release an allocated temporary where the checked ownership conditions require it. |

The prior low and shared closures call the selected outer writers and compare the returned word against `0x8000000000000004`; `closure-guards.tsv` retains the two contextual result guards. The earlier builder packet identifies the subsequent Keccak work. `lsda-headers.tsv` and `lsda.tsv` retain 16 selected exception tables and 115 call-site rows; `lsda-call-links.tsv` maps 125 selected direct calls using return-PC minus one, of which 50 select a nonempty landing pad. For example the low collector's call to the earlier slot collector at `0x26b37d0` has landing `0x26b3866`, whose bytes save the accumulated count and resume unwinding. Actions, personalities, all indirect callees and rollback remain unresolved.

### Conditional examples and comparisons

For successful direct writes with valid, disjoint inputs, the selected array markers predict empty-book input `90` for zero DEX entries and `9191929090` for one DEX containing one book with two empty sides. `empty-book-examples.tsv` contains 12 such constructed shapes and their conditional row Keccak-256 values. The second example predicts `566ded25335bb38527883d14192ca9592e38cbcdcca59227ae3f5a65e96e404c`.

`one-order-example.tsv` constructs one DEX, one book, one first-side level and one order, with price, sizes, oid and core `l` equal to 1, an all-zero user, tif tag 5, core `s = B`, canonical absence tags and the selected named writer mode. Assuming the prior prefixed-hex primitive, compatible writer configuration and successful helpers, it predicts a 120-byte input and row digest `0749c133f9343991106afb30f47924123c88173060fb76730a65643c7ba05546`. This is a synthetic calculation, not a captured node result or a final app hash. An independent minimal reader in the tests checks the nested shape and named-field order. The hash model uses the earlier rate and delimiter observations and 24 round constants read from this ELF; it matches standard Keccak known answers and Python SHA3-256 with the SHA-3 delimiter across rate boundaries.

The six low/shared writer FDE pairs have equal lengths but differ in raw bytes: `paired-fdes.tsv` and `raw-differences.tsv` retain 117 unmasked difference runs. No bytes are normalized. Equal sizes and selected common patterns do not prove semantic or binary equivalence.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Build scope, compiler and linker settings, two-build result, target-generated behavior fixtures, reconstruction-to-target comparison, normalization masks, complete helper and relocation closure, and whole-ELF comparison: **not yet measured**. The model examples are conditional predictions; the captured target was not executed.

## Results and limitations

`summary.json` reports 26 selected FDE ranges totaling 26,127 bytes, 79 byte windows including 32 prior contexts, 360 selected branches, 135 selected relative transfers, 26 labelled decisions, two descriptor relocations, three materializer vector words, seven shared slot-copy rows, two closure guards, 16 LSDA tables, 115 LSDA rows, 11 synthetic slot cases, 12 empty-book examples and one synthetic order example. These are packet selections, not ABCI or whole-binary coverage denominators. The focused suite passes 26 tests without skips, including corrupt digest, unwind extent, byte windows, every selected branch and relative transfer, literal, copy operand, materializer offset, relocation, exception table and out-of-range/NOBITS mapping. Two generations under different hash seeds and time zones match with binutils unavailable. Artifact verification and catalogue checking pass; the repository-wide suite was not run under the stated memory constraint.

No ABCI progress gate is requested; the component remains 0/4. Loader-to-builder live object identity, the full loaded-state handoff, all order and value variants, nested helper behavior, cycle handling, scheduling, all state-root rows, and the complete begin/action/end-block paths remain open. **Next question:** can an unowned post-loader handoff prove that the materialized vector reaches the low builder while its book and borrowed slot allocations remain valid?
