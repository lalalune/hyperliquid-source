# RE-007: Node #115 `dex-registry` Pure Business-Logic Compiled-Byte FDE Matches (`31 FDEs / 5,124 B`)

## Scope & Target

- **Target binary**: `artifacts/node/115/hl-node` (`105,896,032` bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).
- **Component**: `dex-registry` (`l1/src/dex_registry/{perp_dex,clearinghouses}.rs` — Stream E2 / `RE-007`).
- **Compiler & Flags**: `rustc 1.95.0 (59807616e 2026-04-14)` (`--edition=2021 --crate-type=bin -C opt-level=3 -C overflow-checks=yes -C relocation-model=pie -C codegen-units=1 --emit=obj`).
- **Disjointness & Safety**: `#![forbid(unsafe_code)]`, 0 external crates.io dependencies, 0 internal overlaps, 0 overlaps with `research/byte-windows.json` or any sibling compiled-byte packet (checked across both `start`/`end` and `start_va`/`end_va`).

## Matched Non-Visitor Business-Logic FDE Families (`31` FDEs, `5,124 B`)

1. **`PerpDexes::get` / `get_mut` (`l1/src/dex_registry/perp_dex.rs:29,34`, `2 × 113 B = 226 B`)**: `0x4201750`, `0x42017d0`.
2. **`Clearinghouses::get` / `get_mut` (`l1/src/dex_registry/clearinghouses.rs:11,17`, `3 × 113 B = 339 B`)**: `0x446b2f0`, `0x446b370`, `0x446b3f0`.
3. **`Clearinghouses::get_by_asset` (`asset / 10_000`, `3 × 133 B = 399 B`)**: `0x276d060`, `0x5b00e50`, `0x5b00ee0`.
4. **`Exchange::clearinghouse_by_asset` (`+0x7c8` & `+0x1338`, `7 × 139 B = 973 B`)**: `0x2753a70`, `0x5aed6d0`, `0x2a8b2e0`, `0x2a8b370`, `0x55e93a0`, `0x5aed760`, `0x55e9310`.
5. **`Exchange::perp_dex_by_asset` (`+0x3ac8` & `+0x4638`, `3 × 139 B = 417 B`)**: `0x5aed7f0`, `0x2753b00`, `0x5aed880`.
6. **`Exchange::perp_book_by_asset` (`(asset / 10_000, asset % 10_000)` -> `books.get(local).unwrap()` & `books[local]`, `3 × 192 B + 5 × 198 B = 1,566 B`)**: `0x2753ed0`, `0x5aedf90`, `0x5aee050`, `0x276e000`, `0x5b03ae0`, `0x276e0d0`, `0x5b03a10`, `0x276e1a0`.
7. **`Exchange::perp_book_summary` (`3 × 232 B = 696 B`)**: `0x2753750`, `0x5aed180`, `0x5aed090`.
8. **`Clearinghouses::get_by_name` / `get_mut_by_name` (HIP-3 DEX short-name scan, `2 × 254 B = 508 B`)**: `0x446af70`, `0x446b070`.

## Verification

```bash
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-007-node115-dex-registry-logic-byte-matches/verify.py --self-test
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_dex_registry_logic_byte_matches_115 -v
(cd research/work-items/RE-007-node115-dex-registry-logic-byte-matches && sha256sum -c MANIFEST.sha256)
```
