# RE-008: node #115 EMA byte-helper evidence

- FDE `[0x4d2c320, 0x4d2ca28)`, 1800 bytes, entry offset `0xf161d8`.
- Body SHA-256: `2aacf0bbbda27794fd2736c4a29c5d6f588010388ad38caf169c6f2cf87fbd09`.
- Loads root and count at `+0xba`, stages a byte tag and qword at indexed `+0x0`/`+0x8`, copies the remaining 16-byte record range, decrements/stores the count, and reloads the selected entry.
- Capacity and empty-root guards are recorded with a direct edge; short descendant branches remain instruction witnesses. Source-level types and ownership remain unresolved.
