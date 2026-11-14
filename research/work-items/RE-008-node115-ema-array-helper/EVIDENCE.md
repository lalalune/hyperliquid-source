# RE-008: node #115 EMA array helper evidence

- FDE: `[0x4d25fe0, 0x4d26bc6)`, 3046 bytes, entry offset `0x12f23c0`.
- Body SHA-256: `f46db2929f342c40857a9687b3f7f99d486a30d2d1354629507dd15a13c64343`.
- `0x4d26004..0x4d2601f` loads the root pointer, 16-bit root count at `+0x246`, and an indexed record base derived from the current index.
- `0x4d2604d..0x4d26066` computes the remaining count and calls the indirect copy/resize slot at `0x64df568`; the same slot is reused for the adjacent 32-byte record block.
- `0x4d260a9..0x4d260b1` decrements and stores the root count, then reloads the selected entry pointer at `+0x08`.
- The helper has explicit empty, capacity, aggregate-count, and index-order guards before descending; the packet records representative direct edges.
- `0x4d261a6..0x4d2621a` writes the child count and copies the staged `+0x168`/`+0x178` record fields back into the selected record.
- `0x4d262c3..0x4d262e4` advances the tail slot and copies the remaining 8-byte slot range.

These are instruction-level observations only. Allocator semantics, ownership, and full path reachability remain unresolved; no Rust implementation or component-gate change is proposed.
