# RE-005: Node #115 `serialization` (`z_forks/bincode-fork`) 19/19 (100.00%) CGU Identity Closure

Component: `serialization` (`z_forks/bincode-fork`).
Target: Linux x86-64 node #115 (`artifacts/node/115/hl-node`), SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

## Summary

Closes the **19th and final FDE** of the `z_forks/bincode-fork` CGU (`0x1607c70..0x1609aaa`,
`7,575 B` total FDE bytes) using the exact node #115 release profile
(`rustc 1.95.0 (59807616e 2026-04-14)`, `opt-level = 3`, `lto = "thin"`,
`overflow-checks = true`, `#[global_allocator] tikv_jemallocator::Jemalloc` `0.6.0`):

- **New zero-overlap window (`209 B`, `189/209 = 90.43%` raw-equal, 5 relocations, 0 non-reloc diffs)**:
  - `0x1609960..0x1609a31` (`drop_in_place::<std::io::Error>`, vtable `0x64032c8`, jemalloc `sdallocx` GOT `0x64df4a0 -> 0x635de30`).
- **Simultaneous 19/19 (100.00%) CGU live-rebuild proof**:
  - In `--rebuild` mode, the exact same 2-crate ThinLTO + `tikv-jemallocator` build reproduces **all 19/19 CGU FDEs (`7,575 / 7,575 B = 100.00%`, `6,779 / 7,575 = 89.49%` raw-equal)** at 100.00% relocation-qualified equality (the 1 new FDE here + 12 from `RE-005-node115-bincode-fork-cgu-thinlto-matches` + 4 from `RE-005-node115-bincode-fork-gate-closure` + 2 from `RE-012-node115-stream-c-byte-matches`).
  - Combined with the 4 business-logic `bincode::varint` slow-path FDEs (`0x5822490` 293 B, `0x58225c0` 316 B, `0x5822700` 14 B, `0x5822710` 316 B = `939 B`) in `RE-005-node115-bincode-fork-gate-closure`, total verified `z_forks/bincode-fork` compiled-byte identity reaches **8,514 B (23 FDEs)**.
- **Data-table & relocation identity verified**:
  - `.data.rel.ro` `0x6403308` (13 `IntegerType` pointers) + `.rodata` `0x46aa30` (13 lengths)
  - `.rodata` `0x46a86c` (18-arm `DecodeError` jump table)
  - `.data.rel.ro` `0x64032c8 -> 0x1609960` vtable & GOT `0x64df4a0 -> 0x635de30` (`sdallocx`).

## Reproduce

```sh
# Fast offline check (committed bodies.bin + data tables + disjointness + 4 negative controls):
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-005-node115-bincode-fork-cgu-100pct-identity/verify.py --self-test

# Full live offline ThinLTO + tikv-jemallocator rebuild proving all 19/19 CGU FDEs = 7,575/7,575 B (100.00%):
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-005-node115-bincode-fork-cgu-100pct-identity/verify.py --rebuild --self-test

PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_bincode_fork_cgu_100pct_115 -v
```
