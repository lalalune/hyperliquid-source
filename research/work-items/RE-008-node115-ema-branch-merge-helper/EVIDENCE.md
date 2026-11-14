# RE-008: node #115 EMA branch-merge helper evidence

- FDE `[0x4d2e270, 0x4d2e479)`, 521 bytes, entry offset `0xf16278`.
- Body SHA-256: `ade8c3a66de58d1d3703ecb4e9349adb255497bb2b9a802e55202d8a8c9be6a4`.
- The helper reads the root and selected index, stages a 16-byte record plus a descriptor field, calls an indirect copy helper, decrements the root count at `+0xe6`, and reloads the descriptor selected path.
- It records both child/sibling branches, the `count >= 0xc` capacity edges, empty-root guard, and final result writes at offsets `+0x10`, `+0x00`, `+0x18`, `+0x20`, and `+0x28`.
- Witnesses and mutation controls are local byte checks only. They do not establish source-level types, ownership, or runtime equivalence.
