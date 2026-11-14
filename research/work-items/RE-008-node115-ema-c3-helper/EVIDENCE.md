# RE-008: node #115 EMA c3-helper evidence

- FDE `[0x4d2c060, 0x4d2c31f)`, 703 bytes, entry offset `0xf16188`.
- Body SHA-256: `b1cebe748d290819bbe12608e8ed4119c6baa65ecd38d62a0ed0eeaf294aee8a`.
- Loads root and count at `+0xe6`, stages indexed fields at `+0x60`/`+0x68`, performs indirect copy calls, decrements/stores the count, and reloads the selected entry.
- Capacity and empty-root guards are recorded with direct edges; the short descendant branch remains an instruction witness. Source-level types and ownership remain unresolved.
