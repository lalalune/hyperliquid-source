# RE-008: node #115 EMA struct-chain helper evidence

- FDE `[0x4d30060, 0x4d3041d)`, 957 bytes, entry offset `0xf163c0`.
- Body SHA-256: `829df9f31ee511a6fb9aec13f54cd73b0f49accef032c5539a74da9144cbd944`.
- The helper follows a linked chain using selector `+0x4ae` and link `+0x4b0`, stages multiple vector fields, replaces an indexed record, and relinks descendants.
- It records the empty-root edge and structured result writes through offsets `+0x00`, `+0x10`, `+0x20`, `+0x30`, `+0x40`, `+0x50`, and `+0x60`.
- Witnesses and mutation controls are local byte checks only; no source-level equivalence or runtime claim is made.
