# RE-008: node #115 EMA byte-helper evidence

- FDE `[0x4d2c320, 0x4d2ca28)`, 1800 bytes, FDE VA `0xf161d8`.
- Body SHA-256: `2aacf0bbbda27794fd2736c4a29c5d6f588010388ad38caf169c6f2cf87fbd09`.
- Loads root and count at `+0xba`, stages a byte tag and qword at indexed `+0x0`/`+0x8`, copies the remaining 16-byte record range, decrements/stores the count, and reloads the selected entry.
- Capacity and empty-root guards are recorded with a direct edge; short descendant branches remain instruction witnesses. Source-level types and ownership remain unresolved.

Task RE-001. This packet records the selected behavior of one bounded node #115 code interval. The EMA label identifies the submitted packet sequence. Source ownership and runtime reachability remain open. Reviewed static incoming edges to `0x4d2c320` include `0x4d32b05` (`0x4d329f0` FDE, call), `0x4d32bbd` (`0x4d329f0` FDE, call).
