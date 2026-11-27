# RE-009: Node #115 Non-Visitor `storage` & `abci` ThinLTO `#[derive(Debug)]` Compiled-Byte FDE Matches

- **Target release**: Linux x86-64 node #115 (`artifacts/node/115/hl-node`, `105,896,032` bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).
- **Components**: `storage` (`db/src/{rocks_db,db_hub}.rs`), `abci` (`l1/src/abci/`, `l1/src/context.rs`).
- **Compiler profile**: `rustc 1.95.0 (59807616e 2026-04-14) --edition=2021 --crate-name storage_abci_dbg -C opt-level=3 -C overflow-checks=yes -C lto=thin -C save-temps` (`#![forbid(unsafe_code)]`, 0 external deps).
- **Static verification only**: Captured binary is never executed.

## Summary

Live-compiles `main.rs` and verifies **22 non-overlapping, 100.00% relocation-qualified non-visitor first-party `.text` FDE matches** totaling **6,785 bytes** (**6,000 / 6,785 = 88.43% raw-equal**, 0 non-relocation byte diffs):

- **`storage` (3 windows / 978 B)**:
  - `DbWriteError::fmt` (`InvalidMarkerWrite` / `InvalidDataWrite`): `0x25eaba0`, `0x3d525a0`, `0x57d0ec0` (3 × 326 B = 978 B).
- **`abci` (19 windows / 5,807 B)**:
  - `Context::fmt` (all 13 fields of `l1::context::Context`): `0x27726a0` (810 B).
  - `Result<OkNiche, Err>::fmt` (`AbciDigest` result formatter, `cmp word ptr [rax], 2`): `0x2772da0` (517 B).
  - `AbciDigest::fmt` / `&AbciDigest::fmt`: `0x2787d20`, `0x2e36f90`, `0x56599b0`, `0x5aaa250`, `0x5b555e0` (5 × 293 B) + `0x53d55c0` (296 B) = 1,761 B.
  - `L1Hash::fmt`: `0x4545400`, `0x564b200`, `0x5a8aed0` (3 × 293 B = 879 B).
  - `SystemNonce::fmt`: `0x2787580` (293 B).
  - `Hardfork::fmt` / `&Hardfork::fmt` (`version`, `round`): `0x2772400`, `0x4d9ab80`, `0x2787940`, `0x2cd5190`, `0x2e33800`, `0x59675e0`, `0x5aa9630` (7 × 221 B = 1,547 B).

## Verification

```bash
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-009-node115-storage-abci-debug-byte-matches/verify.py --self-test
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_storage_abci_debug_byte_matches_115 -v
```
