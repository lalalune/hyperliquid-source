# RE-001: Node #115 First-Party `serde::Serialize` Wave 3 (`K1`/`K2`/`K2S` Exact-Offset Structs) ThinLTO Census

- **Task**: `RE-001` (first-party compiled-byte reconstruction)
- **Target**: `artifacts/node/115/hl-node` (Linux x86-64 ELF, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`)
- **Toolchain**: `rustc 1.95.0 (59807616e 2026-04-14)`, `opt-level = 3`, `overflow-checks = true`, `lto = "thin"`, `tikv-jemallocator = "=0.6.0"`, `serde = "=1.0.229"`, `serde_json = "=1.0.140"`, `rmp-serde = "=1.3.0"`
- **Consolidation prefix**: `node115-fp-ser3-*`

## Summary

Wave 3 scales the Slice 26/27 `CollectStrTrigger` + `pin_ser` breakthrough to **81 curated, strictly first-party Hyperliquid multi-field struct families** with mixed inlined and out-of-line `serde_json` (`PrettyFormatter` / `CompactFormatter`) field serialization (`K1` / `K2` / `K2S`), adding **`+102,977 B` (+100.56 KB)** across **186 complete `.text` FDEs** and **20 first-party components** (pushing repository first-party compiled-byte coverage past **1.00 MB**!).

Key codegen insight:
- Under `serde_json::Serializer` (`PrettyFormatter` and `CompactFormatter`), each serialized struct field lowers to one of three exact x86-64 call shapes:
  - **`K1`** (out-of-line `Compound::serialize_field(&mut state, "key", &self.field)` with `&self.field` in `%rcx`).
  - **`K2`** (inlined `serialize_key("key")` + `": "` / `":"` + fallible out-of-line `T::serialize(&self.field, serializer)` with `(&self.field, ser)` in `(%rdi, %rsi)`).
  - **`K2S`** (inlined `serialize_key("key")` + `": "` / `":"` + fallible out-of-line collection/slice helper with swapped `(ser, &self.field)` arguments in `(%rdi, %rsi)`, e.g. `MultiSigThreshold`).
- Using `#![forbid(unsafe_code)]` `#[repr(C)]` exact 1-byte-precise offset structs with explicit `K1`/`K2`/`K2S` field types and manual `SerializeStruct` field ordering reproduces **186 complete `.eh_frame` `.text` FDEs (`+102,977 B`, mean `553.6 B`/FDE)** with **100% (`186/186`)** direct PC32 `.rodata` field-name authentication.

### Verified Yield

- **Total matched windows**: **186** complete `.eh_frame` `.text` FDEs (**`102,977 B`**, **100.00% relocation-qualified** via `tools/byte_progress.compare` with 0 relaxations, 0 overlaps internally, with `research/byte-windows.json`, or with any committed sibling packet)
- **Active matched families**: **81 / 81** curated pure Hyperliquid first-party struct families (all third-party `alloy`/`revm`/`reth`/`ethers`/`jsonrpsee` structs and all ambiguous 1–2 char families strictly excluded; 0 `core`/`alloc`/`std`, 0 `drop_in_place`)
- **Anchor mode**: **100% `rodata`** (`186w / 102,977 B` direct PC32 `.rodata` field-name authentication)
- **Matched across 20 first-party components**:

| Component | Windows | Bytes |
|---|---:|---:|
| `consensus` | 47 | 30,820 |
| `dex-registry` | 22 | 12,353 |
| `orderbook` | 14 | 8,166 |
| `risk` | 14 | 8,128 |
| `evm` | 9 | 6,272 |
| `node-runtime` | 18 | 5,937 |
| `foundation` | 9 | 4,994 |
| `abci` | 7 | 3,291 |
| `l1-shared` | 5 | 2,981 |
| `vaults` | 5 | 2,849 |
| `assets` | 7 | 2,810 |
| `exchange` | 4 | 2,390 |
| `staking` | 4 | 2,360 |
| `transport` | 4 | 2,342 |
| `fees` | 4 | 1,940 |
| `action-dispatch` | 5 | 1,840 |
| `bridge` | 3 | 1,377 |
| `action-wire` | 3 | 1,135 |
| `evm-rpc` | 1 | 565 |
| `info-api` | 1 | 427 |
| **Total** | **186** | **102,977** |

## Strict Admission & Hygiene Gates

1. `#![forbid(unsafe_code)]` Rust source (`harness/src/main.rs`) built strictly offline with `--offline --locked`.
2. Harness-only CGUs (`hl_node115_serialize_wave3_census-*.rcgu.o`, excluding `.rcgu.o.rcgu.o`) and harness-only `serde_core::ser::Serialize::serialize` symbols (`SerStructFam*`); zero `core::`/`alloc::`/`std::`/third-party attribution and zero `drop_in_place`.
3. Complete `.eh_frame` `.text` FDE boundaries, `size >= 24`, `relocation_bytes * 2 <= size`, `unmasked >= 12`, and `100.00%` relocation-qualified via `tools/byte_progress.compare` (0 relaxations).
4. Exact `.rodata` field-name anchor authentication (`>= min(expected_count, 2)` distinct expected field strings per FDE).
5. Zero overlaps across `start`/`end` and `start_va`/`end_va` against `research/byte-windows.json` and all committed sibling packets (including Wave 1 `RE-001-node115-first-party-serialize-census`, Wave 2 `RE-001-node115-first-party-serialize-wave2-census`, and all Wave 1–4 Deserialize packets).

## Verification

```sh
(cd research/work-items/RE-001-node115-first-party-serialize-wave3-census && sha256sum -c MANIFEST.sha256)
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-001-node115-first-party-serialize-wave3-census/census.py --rebuild --self-test
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_first_party_serialize_wave3_census_115 -v
```
