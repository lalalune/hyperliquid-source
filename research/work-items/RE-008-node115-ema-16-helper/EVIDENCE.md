# RE-008: node #115 EMA 16-byte-helper evidence

- FDE `[0x4d2ca30, 0x4d2d699)`, 3177 bytes, entry offset `0x12f2660`.
- Body SHA-256: `c64b5930b8c497e3a78c5614b3a4b79254ba3b0456d58fba686270d845d3a559`.
- Loads root and count at `+0x196`, stages indexed fields at `+0xb8`/`+0xc8`, performs indirect copy calls, decrements/stores the count, and preserves the staged record for the next branch.
- Capacity and empty-root guards are recorded with a direct edge; short descendant branches remain instruction witnesses. Source-level types and ownership remain unresolved.
