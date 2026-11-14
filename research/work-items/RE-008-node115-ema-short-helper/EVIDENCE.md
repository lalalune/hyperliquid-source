# RE-008: node #115 EMA short-helper evidence

- FDE `[0x4d29e00, 0x4d2a10e)`, 782 bytes, entry offset `0xf160e8`.
- Body SHA-256: `a83ab47cb019d9fa8be750a79624326f43c71ad19b909a503f76eb31960db52d`.
- Loads root and count at `+0x1ee`, stages indexed `+0x110`/`+0x120` fields, copies the tail range, decrements/stores the count, and reloads the selected entry.
- Explicit capacity, empty-root, and descendant-count short branches are preserved as byte-level witnesses. Source-level types and ownership remain unresolved.
