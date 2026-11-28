# RE-009 · Node #115 PMI root capture

The named checkpoint writer uses `pmi` for the compact exchange field at box `+0x42b0`. It passes that offset at `0x54815b5`, and the corresponding root slot 54 uses the 21-byte descriptor `0x64a87c8` with visitor `0x4d3f050`. Target ELF SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Base `2da45cb0a761cff6b478e40421699857d87a94df`.

The visitor requires a non-leaf destination with two 0x18-byte entries. A leaf destination returns 1. A wrong entry count returns 3. For source byte 1, it advances the data pointer by one, initializes entry 0 when it is empty, and dispatches that entry through `0x41f8050` and relocated slot `0x64df600` to `0x141b9b0`. The child copies the first 16 bytes and then four bytes from the advanced pointer, with the direct and buffer-growth paths both using width 20. These are source bytes `+1..+0x14`, without the source tag. If the child returns 4, entry 1 receives the raw little-endian qword 1. A non-4 child result bypasses that append.

For every other source byte, entry 0 is untouched and entry 1 receives little-endian qword 0. In a fresh two-entry destination that leaves entry 0 absent. Thus an absent payload differs from a present all-zero 20-byte payload even though a zero-filled local representation might make both look empty. The discriminator leaf compares the captured branch, and the body leaf compares that branch's bytes. A field name, live reference, or type label beyond the verified `pmi` name and 20-byte width is unnecessary to test this boundary. Actual H/H+1 values remain open.

[The slot catalogue](../RE-008-abci-hash-slots-115/README.md) establishes the root descriptor. [#6899](https://github.com/lalalune/hyperliquid-source/pull/6899) identifies tag tests and helper calls without mapping the byte source or constants to this root slot. [#7303](https://github.com/lalalune/hyperliquid-source/pull/7303) maps checkpoint keys to root inputs, and [the 110-byte variant packet](../RE-009-node115-root-110-leaf-widths/README.md) identifies the shared width-20 helper in another caller. This packet ties that helper and its discriminator routes to `pmi`.

## Reproduce

From the repository root with the pinned artifact available:

```sh
python3 -B research/work-items/RE-009-node115-root-pmi-capture/verify.py
```

The verifier reads the ELF offline and checks its digest, unwind-indexed [disassembly bytes](windows.txt), slot and name mappings, discriminant data, and relocation destinations. [Measured offline output](offline-log.txt).
