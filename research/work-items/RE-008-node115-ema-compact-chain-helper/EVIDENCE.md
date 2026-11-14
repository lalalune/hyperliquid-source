# RE-008: node #115 EMA compact-chain helper evidence

- FDE `[0x4d30700, 0x4d3098b)`, 651 bytes, entry offset `0xf1643c`.
- Body SHA-256: `d89e1e44dd0b56b36f401191ece7471ba97cf810202318411e6441e0a186498b`.
- The helper walks a compact linked chain using selector `+0xe6` and link `+0xe8`, stages a selected record, replaces indexed fields, and relinks descendants.
- It records the empty-root edge and result writes at `+0x00`, `+0x10`, `+0x18`, `+0x20`, and `+0x28`.
- Witnesses and mutation controls are local byte checks only; no source-level equivalence or runtime claim is made.
