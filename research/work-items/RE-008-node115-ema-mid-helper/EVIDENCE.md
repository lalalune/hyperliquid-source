# RE-008: node #115 EMA mid-helper evidence

- FDE `[0x4d28630, 0x4d29252)`, 3106 bytes, entry offset `0x12f2510`.
- Body SHA-256: `0491d40a8a75ebbaaf6f8ec7f14e7a248c831f9fd456715bc2732d1e41faa1b2`.
- Loads root and count at `+0x1ee`, stages indexed record fields at `+0x110`/`+0x120`, copies the tail range, decrements/stores the count, and reloads the selected entry.
- Capacity, empty-root, and descendant-count guards are represented by direct edge witnesses. Source-level types and ownership are unresolved.
