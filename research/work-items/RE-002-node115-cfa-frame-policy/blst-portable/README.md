The selected mixed-CFA range 0x5d20100..0x5d21214 has a reproducible body match to BLST's published portable blst_sha256_block_data_order assembly. The complete 4,372-byte source function and target range agree at all 4,360 bytes outside three four-byte source relocations. Nine raw differing bytes are confined to those twelve fields. Both GNU and LLVM exported every byte in 1,295 instructions for each body.

The reference comes from the Apache-2.0 source in BLST commit 54e6e55674722fc2797ebb4bbb71b26d881eb4b8. Its generated source blob is identical in v0.3.15, v0.3.16 and v0.3.17. The portable source is preprocessed with __BLST_PORTABLE__=1 and assembled with the system GNU assembler. The original source and its license are retained verbatim. The reproduction and comparison code are independently authored under this project's MIT license.

| Source relocation | Body offset | Type | Addend | Observed target address |
| --- | --- | --- | --- | --- |
| __blst_platform_cap | 0x0a | R_X86_64_PC32 | -8 | 0x65000d0 |
| K256 | 0x65 | R_X86_64_PC32 | -4 | 0x956d80 |
| .Lblst_sha256_block_data_order$2 | 0x14 | R_X86_64_PLT32 | -4 | 0x5d21248 |

Only these source relocation fields are masked. Their opcode prefixes, unresolved reference bytes, offsets, symbol names and addends are checked before comparison. The linked values follow S = P + encoded_displacement - addend. These addresses record outgoing references. Their complete target identities, data contents and behavior remain unresolved. The separate .eh_frame relocation is retained in reference-object.json but is outside the code-byte mask.

Run from the repository root on Linux with Python 3.12, CPP 13.3, GNU binutils 2.42 and LLVM objdump 18.1.3 available on PATH. The binary is read as data. Choose a fresh ignored output path.

```sh
python3 -I -B research/work-items/RE-002-node115-cfa-frame-policy/blst-portable/reproduce.py \
  --binary artifacts/node/115/hl-node --out work/cfa-blst-portable
```

The script authenticates the full target digest and pinned source before creating outputs, rebuilds the source object and compares every unmasked byte. It verifies complete GNU/LLVM native byte coverage and the frozen comparison and controls. The original readelf output independently records the object's symbols and relocation fields. It rejects an altered unmasked byte, a removed relocation, a changed relocation addend and a wrong full target digest. A regenerated result is retained under the output directory's output/ subdirectory.

The original hosted job passed in 35 seconds with uid/gid 65534, zero capabilities, no-new-privileges, an isolated network namespace containing only loopback, readonly inputs and nonexecutable working storage. The selected original receipts retain the reference object as hex, the object decodes, symbol/relocation output, commands, versions and isolation qualification. hosted-receipt-index.json binds the full original archive, including target exports whose byte streams were independently reconciled with the parent packet's retained native exports. Paths printed in native headers depend on the reproduction directory. The logical comparison and controls are compared with the frozen records.

The observed body match supplies a public handwritten assembly counterpart for this existing CFA example. The exact historical source producer, unique BLST release, complete dependency build, unwind equivalence and first-party Rust force-frame-pointers setting remain unresolved. The parent frame_pointers field and component gates stay unresolved.

The registry entry is attributed to native-libraries. The pre-existing vendor census already contains other BLST matches. Its current registered intervals do not overlap this selected body.

[Original hosted comparison](https://github.com/clutchpbcfo/hyperliquid-source/actions/runs/42062457466)
[Pinned BLST source](https://github.com/supranational/blst/blob/54e6e55674722fc2797ebb4bbb71b26d881eb4b8/build/elf/sha256-portable-x86_64.s)
