# Evidence

- `excerpts.objdump.txt` records the pinned bytes and disassembly for the complete FDE extent.
- The entry checks the root pointer, loads the hop count, walks links through offsets `0x42a` and `0x430`, and uses an eight-hop unrolled loop.
- The later block stages a 0x58-byte record, compares a selected index against the node count, relinks the selected entry, and copies SIMD-backed fields into the result.
- `verify.py` independently checks the artifact, FDE extent, body digest, instruction witnesses, root-edge target, and mutation controls.
