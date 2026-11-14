# RE-008: node #115 EMA root-helper evidence

- FDE `[0x4d24f70, 0x4d256d8)`, 1896 bytes, entry offset `0xf16048`.
- Body SHA-256: `b52853d538bd4371f7c9f8aea4db3487f959fd4c47cd8ad65110b5448d664fb3`.
- Entry loads root pointer, 16-bit count at `+0x8e`, and indexed record fields at `+0x60`/`+0x64`; two indirect copy calls stage the record and tail slots.
- The helper decrements/stores the root count, reloads the selected entry at `+0x08`, and branches separately for capacity, empty root, and descendant count.
- Descriptor fields preserve root, index, child pointer, and next index across the recursive path. Source-level types and ownership remain unresolved.
