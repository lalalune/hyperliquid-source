# RE-008: node #115 EMA short-helper evidence

- FDE `[0x4d29e00, 0x4d2a10e)`, 782 bytes, FDE VA `0xf160e8`.
- Body SHA-256: `a83ab47cb019d9fa8be750a79624326f43c71ad19b909a503f76eb31960db52d`.
- Loads root and count at `+0x1ee`, stages indexed `+0x110`/`+0x120` fields, copies the tail range, decrements/stores the count, and reloads the selected entry.
- Explicit capacity, empty-root, and descendant-count short branches are preserved as byte-level witnesses. Source-level types and ownership remain unresolved.

Task RE-001. This packet records the selected behavior of one bounded node #115 code interval. The EMA label identifies the submitted packet sequence. Source ownership and runtime reachability remain open. Reviewed static incoming edges to `0x4d29e00` include `0x4d32813` (`0x4d326f0` FDE, call), `0x4d3294d` (`0x4d326f0` FDE, call).
