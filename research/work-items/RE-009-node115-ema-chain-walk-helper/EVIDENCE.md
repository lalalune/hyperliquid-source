# Evidence

- `excerpts.objdump.txt` records the pinned bytes and disassembly for the complete FDE extent.
- The entry checks the root pointer, loads the hop count, walks links through offsets `0x42a` and `0x430`, and uses an eight-hop unrolled loop.
- The later block stages a 0x58-byte record, compares a selected index against the node count, relinks the selected entry, and copies SIMD-backed fields into the result.
- `verify.py` independently checks the artifact, FDE extent, body digest, instruction witnesses, root-edge target, and mutation controls.

Task RE-001. This packet records the selected behavior of one bounded node #115 code interval. The EMA label identifies the submitted packet sequence. Source ownership and runtime reachability remain open. Reviewed static incoming edges to `0x4d31430` include `0x51d574f` (`0x51d56a0` FDE, call), `0x51d7fff` (`0x51d7f50` FDE, call).
