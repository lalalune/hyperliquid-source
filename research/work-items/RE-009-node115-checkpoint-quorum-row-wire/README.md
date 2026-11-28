# RE-009 Node #115 checkpoint quorum row wire layout

The selected MessagePack `exchange.advt.qrs` restore path reads a vector of two-element rows. A row pairs an unsigned height with a three-element payload whose first element is a nominal `AbciDigest`. The loader reorders that payload so the digest becomes the final 32 bytes of the in-memory row. This is a prerequisite for reading independently sourced digest evidence from existing checkpoint rows.

- Component: `storage` / `abci`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base: `c2772e3b1c742734af159c2c42c9541c7ebb7ac2`.
- Method: LLVM objdump 23.1.4 and raw ELF byte verification. Addresses are ELF virtual addresses.

## Selected positional route

1. The keyed tracker visitor calls `0x3259070` at `0x33b2fc2` for the `qrs` field. Its fixed-array branch forwards the decoded item count to vector reader `0x38a99c0`. This reader limits its initial reservation to `0x2762` elements. It retains the original count for iteration, calling `0x31eaed0` once per accepted item and appending to a `0x68`-byte stride. The separate growth path is reachable when length equals capacity. The reservation limit therefore is not a wire item-count limit.
2. In the row reader, the normal two-element fast path calls the unsigned scalar slot `0x64e2580` before calling payload reader `0x314d020`. The return writer places the scalar in row `+0` and the payload thereafter.
3. The selected payload sequence reads an `AbciDigest` first via `0x2f52fa0`, passing ten type-name bytes from `.rodata`. Its next two elements use readers `0x333b880` and `0x3324390`. The successful three-element path carries the two 16-byte digest lanes from result stack `+0x19` and `+0x29` through payload assembly to output `+0x40` and `+0x50`.
4. In the full row the leading height shifts those lanes to `+0x48..+0x67`. The vector publication copies the complete `0x68` bytes per row, matching the runtime [quorum row builder](../RE-008-digest-quorum-entry-builder-115/README.md) without borrowing the runtime builder's data source.

The trace identifies the child boundaries and output positions. It does not reconstruct the nested collections or the full range of accepted scalar encodings and alternate markers. The proof is static, does not execute the capture, and supplies no real checkpoint or reference digest. The next compatibility step is to resolve the nested collection payload encodings against a provenance-backed checkpoint.

## Reproduce

```sh
python3 -B research/work-items/RE-009-node115-checkpoint-quorum-row-wire/verify.py
```

[Offline output](offline-log.txt) | [Instruction windows](windows.txt)
