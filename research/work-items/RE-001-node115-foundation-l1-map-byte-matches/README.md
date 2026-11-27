# RE-001: Node #115 `foundation` (`base/src/l1_map/entry.rs`) Business-Logic Compiled-Byte FDE Matches

Component: `foundation` (`base/*`).
Target: Linux x86-64 node #115 (`artifacts/node/115/hl-node`), SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

## Summary

Proves **79 strictly disjoint, zero-overlap, 100.00% relocation-qualified first-party
business-logic FDEs (`19,901 B`, `18,425 / 19,901 = 92.58%` raw-equal, 0 non-relocation
byte diffs)** from `base/src/l1_map/entry.rs` (`L1Map` hybrid small-`VecDeque` /
large-`BTreeMap` `Entry`, `VacantEntry`, `OccupiedEntry` API) live-compiled from pure
`#![forbid(unsafe_code)]` Rust (`lib.rs`, 0 external dependencies) under node #115's
exact compiler profile (`rustc 1.95.0 (59807616e 2026-04-14)`, `opt-level = 3`,
`overflow-checks = true`, `relocation-model = pic`, `lto = off`):

- **`Entry::or_default`**: 60 FDEs (`16,909 B`)
- **`OccupiedEntry::get` / `get_mut`**: 13 FDEs (`1,284 B`)
- **`OccupiedEntry::remove_entry`**: 4 FDEs (`1,208 B`, referencing `.rodata` `"occupied entry index"` at `0x5ee173` and `base/src/l1_map/entry.rs:210:39`)
- **`Entry::or_insert`**: 2 FDEs (`500 B`)

Every matched FDE is verified against:
1. Exact FDE boundaries in `work/index/node-115-fde.tsv` / `.eh_frame`.
2. Direct `.text` RIP-relative reference to an authenticated `.rela.dyn` `.data.rel.ro`
   `panic::Location` for `base/src/l1_map/entry.rs` (`lines 60, 64, 210`).
3. Strict relocation-only comparison via `tools/byte_progress.py::compare` (zero
   non-relocation diffs; only 4-byte ELF `PC32`/`PLT32`/`GOTPCREL`/`GOTPCRELX` fields masked).
4. Zero internal overlaps and zero overlaps with `research/byte-windows.json` and all
   sibling compiled-byte packets (Wave-4 consolidation-safe).
5. Runtime implementation added to `src/node115-base/src/l1_map.rs`.

## Reproduce

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-001-node115-foundation-l1-map-byte-matches/verify.py --self-test
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_foundation_l1_map_byte_matches_115 -v
```
