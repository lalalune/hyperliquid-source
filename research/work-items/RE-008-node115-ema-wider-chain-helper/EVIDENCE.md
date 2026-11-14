# RE-008: node #115 EMA wider-chain helper evidence

- FDE `[0x4d30420, 0x4d306fa)`, 730 bytes, entry offset `0xf163f0`.
- Body SHA-256: `1b8a97ed9885a6303be2fbea560a6b714d7826cd33ed07281f3e45ceb28c28e3`.
- The helper follows a wider linked-node chain using selector `+0x79a` and link `+0x7a0`, stages an `0xa8`-byte selected record, performs two indirect copies, and relinks descendants.
- It records the empty-root edge and result writes through `+0x00`, `+0xb0`, `+0xb8`, and `+0xc0`.
- Witnesses and mutation controls are local byte checks only; no source-level equivalence or runtime claim is made.
