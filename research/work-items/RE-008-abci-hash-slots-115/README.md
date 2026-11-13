# RE-008: node #115 exchange abci hash input (48th stage): 59 slots and their box fields

- Component ID: abci. Question: #6024 (stage 47) found that the digest step builds its hash input in `0x4e34ce0`, which fills 59 preset 0x18-byte slots through `0x54423c0` and hands them to `0x141a250`. It left open which box field each slot covers and what `0x141a250` does.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues open PRs #6023 and #6024. It imports helpers from the merged `tools/freeze_snapshot_115.py` only.
- Claim status: instruction bytes, offsets, relocations, vtable words and the decoded pointer and entry tables are observations. "Slot", "field", "leaf", "tree", "hasher state" and "serialize" are inferred labels from sizes, call shapes and stage 47's BLAKE3 identification. The binary was not executed.
- Scope included: the pointer table and slot vector in `0x4e34ce0`; the entry table, length check and job call in `0x54423c0`; size, alignment and method relocations of the 45 vtables; the leaf and child-skip paths of `0x141a250`. Scope excluded: the vtable method bodies (except the 1-byte one quoted below), the job runner `0x57c3b30`, the inner-node combine after the recursion (`0x141b050`, `0x141c180`), and the names of the box fields. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/abci_hash_slots_115.py --check
python3 -m unittest tests.test_abci_hash_slots_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. It decodes the two table-building ranges with a small decoder that accepts only the instruction forms used there and fails on anything else. The three `*.objdump.txt` files were made with GNU objdump 2.42 for review only; the tool does not read them.

## Evidence 1: the builder's pointer array and slot vector

`0x4e34ce0` writes 74 pointers to `rsp+0x128 + 8i` (`0x4e34d06..0x4e35155`): index 0 is the box base (`mov [rsp+0x128], r15`) and indexes 1 to 73 are `lea rax, [r15+disp32]` field addresses. It then allocates 0x588 bytes (59 x 0x18), presets every slot's first word to `0x8000000000000001`, sets capacity and length to 59, and calls `0x54423c0` with the pointer array and the slot vector (`0x4e35324`). On a result byte of 4 it passes the slot vector to slot `0x64df500` (relocated to `0x141a250`).

## Evidence 2: 59 entries, one per slot

`0x54423c0` stores 59 (data, vtable) pairs at `rsp+0x10 + 0x10k`. Entry 0's data is the pointer array itself (`mov [rsp+0x10], rdi`); its vtable `0x64a8160` describes a 128-byte value, the size of 16 pointers. Entry k >= 1 takes pointer k+15 (`mov reg, [rdi+0x80+8(k-1)]`). It requires the slot vector length to be 59 (`0x5442a2d`) and calls `0x57c3b30` with edx = 59 (`0x54435b7`).

Entry 0 covers the box base and these 15 fields: `+0x7c0 +0x80 +0x7d8 +0x968 +0xb9a +0xb98 +0x9f8 +0x670 +0xb78 +0xa78 +0x9b0 +0xa18 +0xb99 +0xb90 +0xa38`.

Field size is word 1 of the slot's vtable (the size of the value the data pointer points at).

| Slot | Box field | Field size | Vtable |
|---|---|---|---|
| 0 | base + 15 fields (see below) | 128 | `0x64a8160` |
| 1 | `+0x3ac0` | 24 | `0x64a8188` |
| 2 | `+0x3ad8` | 24 | `0x64a81b0` |
| 3 | `+0x3af0` | 360 | `0x64a81d8` |
| 4 | `+0x4158` | 16 | `0x64a8200` |
| 5 | `+0x4168` | 16 | `0x64a8200` |
| 6 | `+0x3c58` | 144 | `0x64a8228` |
| 7 | `+0x41e8` | 24 | `0x64a8250` |
| 8 | `+0xba0` | 488 | `0x64a8278` |
| 9 | `+0x3f08` | 128 | `0x64a82a0` |
| 10 | `+0xd88` | 864 | `0x64a82c8` |
| 11 | `+0x4200` | 32 | `0x64a82f0` |
| 12 | `+0x4220` | 8 | `0x64a8318` |
| 13 | `+0x10e8` | 16 | `0x64a8340` |
| 14 | `+0x4178` | 16 | `0x64a8200` |
| 15 | `+0x4288` | 12 | `0x64a8368` |
| 16 | `+0x4294` | 12 | `0x64a8368` |
| 17 | `+0x4228` | 8 | `0x64a8390` |
| 18 | `+0x3ce8` | 88 | `0x64a83b8` |
| 19 | `+0x3f88` | 32 | `0x64a83e0` |
| 20 | `+0x4188` | 16 | `0x64a8200` |
| 21 | `+0x3fa8` | 32 | `0x64a8408` |
| 22 | `+0x3fc8` | 48 | `0x64a8430` |
| 23 | `+0x42ac` | 1 | `0x64a8458` |
| 24 | `+0x4230` | 8 | `0x64a8480` |
| 25 | `+0x4238` | 8 | `0x64a8318` |
| 26 | `+0x10f8` | 16 | `0x64a84a8` |
| 27 | `+0x4240` | 16 | `0x64a84d0` |
| 28 | `+0x3a00` | 64 | `0x64a84f8` |
| 29 | `+0x3a40` | 64 | `0x64a84f8` |
| 30 | `+0x3a80` | 64 | `0x64a84f8` |
| 31 | `+0x1108` | 9944 | `0x64a8520` |
| 32 | `+0x3d40` | 56 | `0x64a8548` |
| 33 | `+0x4198` | 16 | `0x64a8200` |
| 34 | `+0x3ff8` | 32 | `0x64a8570` |
| 35 | `+0x4018` | 32 | `0x64a8598` |
| 36 | `+0x4038` | 32 | `0x64a85c0` |
| 37 | `+0x37e0` | 16 | `0x64a85e8` |
| 38 | `+0x42ad` | 1 | `0x64a8458` |
| 39 | `+0x4058` | 72 | `0x64a8610` |
| 40 | `+0x40a0` | 32 | `0x64a8638` |
| 41 | `+0x40c0` | 120 | `0x64a8660` |
| 42 | `+0x41a8` | 48 | `0x64a8688` |
| 43 | `+0x41d8` | 16 | `0x64a8200` |
| 44 | `+0x4250` | 24 | `0x64a86b0` |
| 45 | `+0x42a0` | 12 | `0x64a8368` |
| 46 | `+0x42ae` | 1 | `0x64a8458` |
| 47 | `+0x4268` | 8 | `0x64a86d8` |
| 48 | `+0x37f0` | 64 | `0x64a8700` |
| 49 | `+0x4138` | 32 | `0x64a8728` |
| 50 | `+0x42af` | 1 | `0x64a8458` |
| 51 | `+0x3830` | 40 | `0x64a8750` |
| 52 | `+0x3d78` | 32 | `0x64a8778` |
| 53 | `+0x3858` | 176 | `0x64a87a0` |
| 54 | `+0x42b0` | 21 | `0x64a87c8` |
| 55 | `+0x4270` | 8 | `0x64a8480` |
| 56 | `+0x3d98` | 184 | `0x64a87f0` |
| 57 | `+0x3e50` | 184 | `0x64a8818` |
| 58 | `+0x3908` | 248 | `0x64a8840` |

45 distinct vtables cover the 59 slots. Shared ones: `0x64a8200` (slots 4, 5, 14, 20, 33, 43), `0x64a8458` (23, 38, 46, 50: the four 1-byte fields `+0x42ac..+0x42af`), `0x64a8368` (15, 16, 45), `0x64a84f8` (28, 29, 30), `0x64a8318` (12, 25), `0x64a8480` (24, 55). Slot 13 is `+0x10e8`, the layout-A freeze height from #6006.

The 1-byte method `0x1419d40` (vtable `0x64a8458`, method 0) reads the byte at the data pointer, appends it to the buffer at `[rsi+8]` (growing it through slot `0x64df4a8` when full) and returns 4. Inference: method 0 of each vtable serializes its field into the slot's buffer.

## Evidence 3: the tree hasher `0x141a250`

- Leaf: a node whose first word is `0x8000000000000000` (`0x141a264..0x141a27b`) points at a boxed 0x798-byte record. The function copies its 0x778-byte state at `+0x20` (`0x141a292`), feeds the buffered bytes (`+0x8` pointer, `+0x10` length) to slot `0x64df510` -> `0x160b3a0`, finalizes through slot `0x64df518` -> `0x160bcd0` (the BLAKE3 update and finalize from #6024), writes byte 0 then the 32-byte result, and frees the 0x798-byte record (`0x141a331`). If the record's byte `+0x18` is 1 it first calls `0x5c9b900` with the 23 bytes at `0x450102` (`hash error\nfailed to wr...`).
- Inner node: the first word is a capacity; the function walks 0x18-byte children, skips any whose first word is `0x8000000000000001` (`0x141a3c5`), and hashes the rest by a recursive call through `0x64df500` (`0x141a3f1`), collecting each child's index and result.
- Inference: each of the 59 slots becomes one buffered BLAKE3 leaf over its serialized field, and the slot vector is hashed as a tree of those leaves. How children are combined after the recursion is not mapped.

## Implementation and comparison

The tool pins 25 instruction byte runs and 3 relocations, decodes both tables from bytes, and compares them with the pinned expected table. Tests change one byte at a time in a copy of the image and expect rejection (8 mutation tests). Alternatives considered: naming fields from serde strings (no string literals are loaded in either table range; out of scope), and tracing the vtable method bodies (bounded out).

## Results and limitations

- Result: the abci hash input is 59 slots: slot 0 is a group of the box base and 15 fields, slots 1 to 58 are single box fields at the offsets above, all in layout A (#6006).
- Limits: field names; the 44 other vtable methods; `0x57c3b30`; the inner-node combine (`0x141b050`, `0x141c180`); whether stage 47's serializer `0x41c5140` hashes the tree result again; the layout-B builder, if one exists.
- Next lead: the inner-node combine after `0x141a3f1` (how child digests are ordered and hashed together).
