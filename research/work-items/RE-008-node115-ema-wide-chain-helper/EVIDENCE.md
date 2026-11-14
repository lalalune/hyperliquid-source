# RE-008: node #115 EMA wide-chain helper evidence

- FDE `[0x4d2fb90, 0x4d2fe6a)`, 730 bytes, entry offset `0xf16348`.
- Body SHA-256: `fb3b0b157e5c676ab79af41c8aa97a6754fcb8014e1e4ef5e8f37ec004df7bb0`.
- The helper follows a wide linked-node chain using selector `+0x9aa` and link `+0x9b0`, stages a `0xd8`-byte selected record, and calls an indirect copy helper twice.
- It handles empty-root and short-chain branches, updates the selected descriptor, relinks descendants, and writes result fields at `+0x00`, `+0xe0`, `+0xe8`, and `+0xf0`.
- Witnesses and mutation controls are local byte checks only. They do not establish source-level types, ownership, or runtime equivalence.
