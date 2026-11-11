# RE-011: selected transient-map clearing in EVM driver cleanup

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Partial static evidence for [EVM issue #3918](https://github.com/lalalune/hyperliquid-source/issues/3918). The [TLOAD/TSTORE packet](../RE-011-transient-storage-115/README.md) identifies the transient map but leaves transaction clearing open. [PR #4356](https://github.com/lalalune/hyperliquid-source/pull/4356) maps its writer and journal entry, and [PR #4363](https://github.com/lalalune/hyperliquid-source/pull/4363) maps a selected checkpoint-revert branch. This packet follows a different helper, `0x2970360`, through its selected map-reset path and two driver call sites; it does not claim all transaction exits use this path.

The two driver bodies call `0x2970360` at `0x2963f77` and `0x29a284e`, passing stack objects at `rsp+0x1260` and `rsp+0xd80` respectively. The helper first takes the journal-like vector at input `+0x18/+0x20/+0x28`, saves its length, stores length zero and walks `0x58`-byte records backwards. Tag `0x0c` stops the walk. For other selected records it copies the record to temporary storage and invokes relocation slot `0x64e6d68` → `0x5be3400`, with **third argument zero**. The dispatch table's tag-10 entry selects `0x5be372b`; that arm tests the third argument and returns on zero before either of its transient-map helper paths. This is separate from #4363's checkpoint walker, which supplies a nonnull context pointer on its selected path.

The helper then reads an outer-map item count at input `+0x108`. If it is zero, it branches past the described map-reset block. With a nonzero count, it scans control bytes from the pointer at `+0xf0` in 16-byte groups and visits the indicated 64-byte-stride rows. On the selected normal path it invokes an indirect deallocator for each visited row whose nested size word is nonzero, subject to its checked computed-size conditions. It then reads the map mask at `+0xf8`:

- When the mask is nonzero, `0x297052c` calls imported `memset(control, 0xff, mask+0x11)`.
- When the mask is zero, the fill is skipped and the selected growth value is zero.
- Both branches then write item count zero at `+0x108` and a computed growth word at `+0x100`. For a valid nonoverflowing mask below 8 the growth word equals the mask; for mask at least 8 it is `((mask+1) & ~7) - ((mask+1) >> 3)`.

The input-relative `+0xf0/+0xf8/+0x100/+0x108/+0x110` map header is the same layout that the earlier TSTORE writer accesses relative to its own input. The physical objects are the same only if a caller supplies the same context; that identity and concrete transaction reachability are not proved here. Valid map metadata, successful normal deallocation, no conflicting alias writes, ordinary imports and nonoverflowing sizes are premises. The zero-count route does not execute the fill/count/growth stores above. Remaining cleanup fields, exceptional unwinding, ownership, all journal tags and complete transaction commit or rollback are outside scope. No EVM gate is advanced.

## Reproduce

```sh
PYTHONPATH=tools python3 research/work-items/RE-011-node115-transient-map-clear/verify.py
```

The static verifier authenticates four complete indexed FDEs and their decoded partitions, 151 selected spans, 74 instruction pins, eight selected edges, two relocations, the `memset` import, the tag-10 table entry, seven arithmetic examples and seven corruption controls. Capstone 5.0.7 is required. Counts are scoped evidence, not component coverage; no captured instruction is executed or emulated.
