# RE-008: node #115 abci hash tree fold and root digest (49th stage)

- Component ID: abci. Question: open PR #6027 found that the abci hash input builder `0x4e34ce0` fills 59 slots and passes them through slot `0x64df500` to `0x141a250`, and open PR #6024 found that the digest is BLAKE3. It left open how child results are combined into the 32-byte root.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues open PRs #6024 and #6027. It imports helpers from the merged `tools/freeze_snapshot_115.py` and does not depend on unmerged files.
- Claim status: instruction bytes, constants, string bytes, relocations, FDE extents and call censuses are observations. "Leaf", "node", "hasher state", "buffer", "serialise", "hex string" and "BLAKE3" are inferred labels from the sizes, call targets, strings and #6024. The binary was not executed.
- Scope included: all of `0x141a250`; the call shapes of `0x141b050` and `0x141c180`; the first half of `0x41c5140` up to the BLAKE3 IV load; the prefix and digit table of `0x2eabb50`. Scope excluded: the bodies of the serialisers `0x41444a0` and `0x41c6110`, of `0x141b050`, `0x141c180` and `0x5c9b900`, and the callers listed under Limits. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/abci_hash_tree_115.py --check
python3 -m unittest tests.test_abci_hash_tree_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The four `*.objdump.txt` files beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Evidence 1: one recursive function, two shapes

`0x141a250` (FDE `0x141a250..0x141a8bf`) is the only `R_X86_64_RELATIVE` target of slot `0x64df500`. Inside, it calls that slot twice (`0x141a3f1`, `0x141a595`), once per child. Its input's first word picks the shape: `0x8000000000000000` is a leaf (`0x141a264..0x141a27b`), anything else is a Vec of 0x18-byte children.

## Evidence 2: a leaf hashes its own buffer

- The leaf points at a 0x798-byte box: a buffer Vec at `+0x0..+0x18`, a byte at `+0x18`, and 0x778 bytes copied from `+0x20` (`mov edx, 0x778`, memcpy).
- If the byte is 1, it calls slot `0x64df4b8` with a 23-byte slice at `0x450102` that starts `hash error`.
- A non-empty buffer goes to slot `0x64df510` (`0x160b3a0`, BLAKE3 update per #6024). Slot `0x64df518` (`0x160bcd0`, finalize) gives 32 bytes.
- Result: tag byte 0 at `+0x0`, digest at `+0x1..+0x21`. The box is freed with size 0x798.
- Inference: the leaf record is a buffered writer around a BLAKE3 hasher; each slot is a separate hash.

## Evidence 3: a node does not hash

- Children whose first word is `0x8000000000000001` (the preset from #6027) are skipped (`0x141a3c5..0x141a3d2`).
- Each other child is recursed. A child result with tag 2 is also skipped (`cmp byte [rsp+0xf8], 2`).
- Each kept child is stored as a 0x30-byte element: its index (u64), then the 0x28-byte child result. The first allocation is 0xc0 bytes (4 elements); growth goes through `0x141b050` with align 8 and size 0x30 (its only direct call, `0x141a6b3`).
- Result: tag byte 1 and the Vec (cap, ptr, len) at `+0x8`, `+0x10`, `+0x18`. `0x141c180` drops the child iterator on the way out.
- No hash function is called on the node path. Child digests are not combined here.

## Evidence 4: the root hashes the serialised tree

- The digest step `0x548dad0` calls slot `0x64e7820` (`0x41c5140`) at `0x548db1a` with the builder's result.
- `0x41c5140` sets up a serialiser with config `0x400` (#6024) and tests the tag (`cmp byte [rsi], 1`):
  - node: `0x41444a0` serialises the tree;
  - leaf: slot `0x64e4d08` (`0x2eabb50`) writes `0x` (`mov word [rdi], 0x7830`) and lowercase hex from the table `0x455d40` (`0123456789abcdef`) into a 0x42-byte buffer from 32 input bytes; `0x41c6110` serialises that string.
- It then loads the BLAKE3 IV from `0x457ae0` (#6024) and hashes the bytes.
- Inference: root = BLAKE3(serialised tree), where each leaf appears as a `0x`-prefixed 64-digit hex string and each node as its list of (slot index, child) pairs, with empty slots left out.

## Implementation and comparison

The tool pins 27 instruction byte runs, 17 RIP-relative or rel32 references, 5 relocations, the hex table, the leaf error slice and 4 FDE extents, then recomputes the slot-call censuses. Tests mutate one byte in a copy of the image and expect rejection (8 mutation tests). Alternatives considered: emulating the hash (not allowed for this repository); mapping the serialisers' byte format (bounded out).

## Results and limitations

- Result: per-slot BLAKE3 digests are not hashed together pairwise. The tree is serialised with leaves as hex strings, and the root is one BLAKE3 over those bytes.
- Limits: the byte format written by `0x41444a0` and `0x41c6110` (how indices and strings are encoded) is not mapped. `0x5c9b900` is not mapped beyond its call. Two other callers of slot `0x64df500` (`0x269a829`, `0x4e34999`) and four other callers of slot `0x64e7820` (`0x2bb380a`, `0x54846f7`, `0x548d90a`, `0x5646bf0`) are not traced; `0x548d90a` is in the layout-B digest step `0x548d8c0` (#6023). Whether the tree has more than one level for the abci input (whether any of the 59 slots is itself a node) is not decided here.
- Next lead: the serialiser `0x41444a0` for nodes, to fix the exact bytes that go into the root hash.
