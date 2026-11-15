# RE-008: node #115 EMA wide-helper evidence

- FDE `[0x4d26fc0, 0x4d27af6)`, 2870 bytes, FDE VA `0x12f2468`.
- Body SHA-256: `efa3f27223b0eb7517037703eea936089ebef03bf07650dc8335b02a33b34c1b`.
- Entry loads root and count at `+0x16a`, stages an indexed wide record at `+0x60`/`+0x70`, and calls the indirect copy slot for the tail range.
- The helper decrements/stores the count, reloads the selected entry at `+0x08`, and separates capacity, empty-root, and descendant-count branches.
- Descriptor fields preserve root, index, child pointer, and next index across the recursive path. No source-level type or ownership claim is made.

Task RE-001. This packet records the selected behavior of one bounded node #115 code interval. The EMA label identifies the submitted packet sequence. Source ownership and runtime reachability remain open. Reviewed static incoming edges to `0x4d26fc0` include `0x4d33919` (`0x4d337f0` FDE, call), `0x4d33a0d` (`0x4d337f0` FDE, call).
