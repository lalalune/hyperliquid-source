# RE-009: Node #115 First-Party `abci` (`l1/src/abci/state.rs`) Business-Logic Wave 3 Compiled-Byte FDE Matches

## Target
- Binary: `artifacts/node/115/hl-node` (Linux x86-64 ELF, `105,896,032` bytes)
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Toolchain: `rustc +1.95.0`, Rust 2021 edition, `opt-level = 3`, `overflow-checks = true`, `lto = "thin"`, `codegen-units = 256`, `tikv-jemallocator = "=0.6.0"`, `#![forbid(unsafe_code)]`

## Summary
- **4 strictly disjoint pure first-party `.text` FDEs = `4,362 B`** (`3,738 / 4,362 = 85.69%` raw-equal, `100.00%` relocation-qualified via `tools/byte_progress.py::compare` with `0` non-relocation byte diffs, `0` relaxations, `0` `core::`/`alloc::`/`std::`/vendored attribution).
- Component breakdown (verified against `.rela.dyn` -> `.data.rel.ro` `core::panic::Location` records and `research/components.json`):
  - **`abci`**: `4` FDEs = `4,362 B` (`l1/src/abci/state.rs:161,193,195`)

## Matched FDEs
| Component | Label | Source Anchor | VA Range | Size | Raw-Equal |
|---|---|---|---|---:|---:|
| `abci` | `abci_state_serialize_and_save_26a2810` | `l1/src/abci/state.rs:193:56,195:17,64` (copy 1) | `0x26a2810..0x26a2c7e` | 1,134 B | 965 / 1,134 |
| `abci` | `abci_state_serialize_and_save_4e4af80` | `l1/src/abci/state.rs:193:56,195:17,64` (copy 2) | `0x4e4af80..0x4e4b3ee` | 1,134 B | 973 / 1,134 |
| `abci` | `abci_state_serialize_and_save_4e4b3f0` | `l1/src/abci/state.rs:193:56,195:17,64` (copy 3) | `0x4e4b3f0..0x4e4b85e` | 1,134 B | 973 / 1,134 |
| `abci` | `abci_state_serialize_to_vec_4e4b860` | `l1/src/abci/state.rs:161:83` | `0x4e4b860..0x4e4bc20` | 960 B | 827 / 960 |

## Verification
```bash
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-009-node115-storage-abci-logic-wave3-byte-matches/verify.py --self-test
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-009-node115-storage-abci-logic-wave3-byte-matches/verify.py --rebuild --self-test
(cd research/work-items/RE-009-node115-storage-abci-logic-wave3-byte-matches && sha256sum -c MANIFEST.sha256)
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_storage_abci_logic_wave3_115 -v
```
