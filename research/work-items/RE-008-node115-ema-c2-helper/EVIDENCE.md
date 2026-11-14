# RE-008: node #115 EMA c2-helper evidence

- FDE `[0x4d29260, 0x4d29df2)`, 2962 bytes, entry offset `0x12f2564`.
- Body SHA-256: `ef7609725155b9334aad385e6b995a84f1b7342fa5df9eeb3be6cc704e8d9fbd`.
- Loads root and count at `+0x1c2`, stages 32-byte indexed records and `+0x168` tail fields, performs indirect copy calls, decrements/stores the count, and reloads the selected entry.
- Capacity, empty-root, and descendant-count guards are recorded with direct edges. Source-level types and ownership remain unresolved.
