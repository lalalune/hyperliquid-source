# RE-008: node #115 abci digest (47th stage): BLAKE3 over a serialised view of the box

- Component ID: abci. Question: #6023 (stage 46) found that the layout-A step stores (height, digest) pairs computed by `0x548dad0`, and that the step wrappers compare them with quorum values. It left open which hash `0x548dad0` → `0x41c5140` computes and what feeds it.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues #6021 and #6023. It imports helpers from the merged `tools/freeze_snapshot_115.py` only.
- Claim status: instruction bytes, offsets, constants, string bytes, relocations, Location records, FDE extents and call or reference censuses are observations. "BLAKE3", "platform probe", "serialiser", "field table" and "blocking wrapper" are inferred labels from the constants, the vendored path, the state layout and the call shapes. The binary was not executed.
- Scope included: all of `0x548dad0` and `0x41c5140`; the platform probe `0x160bee0`; the reference census of `0x160b3a0`; the field table, slot setup, parts call and fold call in `0x4e34ce0`; the A step call site. Scope excluded: the bodies of `0x54423c0`, `0x141a250`, `0x41444a0`, `0x41c6110`, `0x2eabb50` and `0x4e3a7a0`; the B-layout twin `0x548d8c0`; the observer at engine value `+0x20`. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/abci_digest_hash_115.py --check
python3 -m unittest tests.test_abci_digest_hash_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The four `*.objdump.txt` files beside this record were made with GNU objdump 2.42 for review only; the tool does not read them.

## Evidence 1: the digest step `0x548dad0`

- Its only direct caller is the A step at `0x5a07fce`. There `rsi` is the box, `rcx` is engine value `+0x20` and `rdx` is engine value `+0x330`.
- It reads the clock, then calls `0x4e46090(out, box, 1)` (`0x548db0f`).
- It passes that result to slot `0x64e7820`, which is relocated to `0x41c5140`, with a 32-byte output (`0x548db1a`).
- It records the elapsed seconds with count 1 through slot `0x64e1010` → `0x1547530` into the observer from `rcx`. The Location is `l1/src/abci/abci_hash.rs:28:37` (`0x64aa290`).
- It then calls `0x4e3a7a0` with the height (box `+0x28`) and the 32-byte digest.

## Evidence 2: `0x41c5140` serialises, then hashes with BLAKE3

- Serialiser: a Vec starts at capacity 0, pointer 1 and length 0, with a config dword `0x400` and a zero byte. When the argument's first byte is 1, `0x41444a0` serialises its `+0x8`. Otherwise slot `0x64e4d08` (`esi = 0x42`, `ecx = 0x20`) and `0x41c6110` run.
- Platform: slot `0x64df488` → `0x160bee0` returns 4, 3, 2 or 1 from cached CPU feature bits (`test eax, 0x80000`; `test ecx, 0x2000000`; `shr eax, 10; and eax, 1; inc al`). The byte is stored at hasher state `+0x6b`.
- IV: the 32 bytes at `0x457ae0` are `6a09e667 bb67ae85 3c6ef372 a54ff53a 510e527f 9b05688c 1f83d9ab 5be0cd19`. They are copied twice, as key and as chaining value, and the chunk counter is set to 0.
- Update: slot `0x64df510` → `0x160b3a0`, with the serialised bytes. That function holds 13 RIP-relative references to Location records whose file is `/home/ubuntu/hl/code_Mainnet/z_vendor/blake3/src/lib.rs`.
- Finalize: slot `0x64df518` → `0x160bcd0` writes 32 bytes to the output.

Inference: the digest is BLAKE3 of the serialised value. SHA-256 uses the same eight IV words, but it has no key copy and no platform byte, and the update function names the vendored blake3 crate.

## Evidence 3: the input builder `0x4e34ce0`

- It is reached from `0x4e46090` (two direct calls at `0x4e46129` and `0x4e461c9`), the same blocking-wrapper shape as `0x4e45a30` in #6001.
- It stores 73 references into the box (`lea rax, [r15+disp32]`, first `+0x7c0`, `+0x80`, `+0x7d8`) into a stack table.
- It allocates `0x588` bytes and presets 59 (`0x3b`) 0x18-byte slots to `0x8000000000000001`.
- It calls `0x54423c0(table, slots)`. A result of 4 folds the slots through slot `0x64df500` → `0x141a250`.
- It logs `computed exchange abci hash` with the height and elapsed time.

Inference: the abci digest is BLAKE3 over a serialised value built from per-field parts of the box.

## Implementation and comparison

The tool pins 36 instruction byte runs, 15 references, 6 slot relocations, the IV, the blake3 path, the log text and the Location record, then recomputes the blake3 Location census, the caller census, the 73-entry table and the 59 slots. Tests change one byte in a copy of the image and expect rejection (8 mutation tests). Alternatives considered: matching the SHA-256 K table (absent from these functions); running the hasher (not allowed for this repository).

## Results and limitations

- Result: the abci digest compared in #6023 is BLAKE3 of a serialised value that `0x4e34ce0` builds from 73 box fields in 59 parts.
- Limits: what `0x54423c0` writes per slot and how `0x141a250` folds them; the serialiser format (config `0x400`); which field each slot covers; the B twin `0x548d8c0`; the name of the observer at engine value `+0x20`; what `0x4e3a7a0` does with height and digest.
- Next lead: `0x54423c0`'s per-slot work and the field each of the 59 slots covers.
