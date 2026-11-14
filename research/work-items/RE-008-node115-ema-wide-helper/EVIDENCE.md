# RE-008: node #115 EMA wide-helper evidence

- FDE `[0x4d26fc0, 0x4d27af6)`, 2870 bytes, entry offset `0x12f2468`.
- Body SHA-256: `efa3f27223b0eb7517037703eea936089ebef03bf07650dc8335b02a33b34c1b`.
- Entry loads root and count at `+0x16a`, stages an indexed wide record at `+0x60`/`+0x70`, and calls the indirect copy slot for the tail range.
- The helper decrements/stores the count, reloads the selected entry at `+0x08`, and separates capacity, empty-root, and descendant-count branches.
- Descriptor fields preserve root, index, child pointer, and next index across the recursive path. No source-level type or ownership claim is made.
