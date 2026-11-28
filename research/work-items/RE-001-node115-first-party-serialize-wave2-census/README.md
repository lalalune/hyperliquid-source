# RE-001: Node #115 First-Party `serde::Serialize` Wave 2 (Struct Layouts) ThinLTO Census

- **Task**: `RE-001` (first-party compiled-byte reconstruction)
- **Target**: `artifacts/node/115/hl-node` (Linux x86-64 ELF, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`)
- **Toolchain**: `rustc 1.95.0 (59807616e 2026-04-14)`, `opt-level = 3`, `overflow-checks = true`, `lto = "thin"`, `tikv-jemallocator = "=0.6.0"`, `serde = "=1.0.229"`, `serde_json = "=1.0.140"`, `rmp-serde = "=1.3.0"`
- **Consolidation prefix**: `node115-fp-ser2-*`

## Summary

Wave 2 scales the Slice 26 (`RE-001-node115-first-party-serialize-census`) `CollectStrTrigger` + `pin_ser` breakthrough to **68 verified, strictly first-party Hyperliquid struct families** across `serde_json` (`CompactFormatter` / `PrettyFormatter` / `Value`) and `rmp-serde` (MessagePack `DefaultConfig` / `StructMapConfig` / `HumanReadableConfig`).

Key struct-layout insight:
- Under `serde_json::Serializer` (`CompactFormatter` and `PrettyFormatter`), `<T as serde::Serialize>::serialize` calls `Compound::serialize_field(&mut state, "field_name", &self.field)` by pointer (`%rcx`), so the compiled FDE depends strictly on field count, field-name string lengths, and exact field byte offsets (`+0`, `+8`, `+16`, `+24`, `+32`, ..., `+6944`).
- Modeling each verified Hyperliquid struct's exact field offsets in `#![forbid(unsafe_code)]` safe Rust (using natural `repr(Rust)` layouts, `#[repr(C)]`, and exact `SerializeStruct` field ordering for reordered `repr(Rust)` fields such as `VoteTracker`, `BridgeEthDeposit`, `AbciDigestHash`, `BorrowLendOpReq`, `HorizonAckStatus`, and `BoleAccountHealth`) reproduces **190 complete `.text` FDEs (`+87,914 B`)** across **16 first-party components** — with **100% (190/190)** directly authenticated via RIP-relative PC32 `.rodata` field-name relocations.

### Verified Yield

- **Total matched windows**: **190** complete `.eh_frame` `.text` FDEs (**`87,914 B`**, **100.00% relocation-qualified** via `tools/byte_progress.compare` with 0 relaxations, 0 overlaps internally, with `research/byte-windows.json`, or with any committed sibling packet)
- **Active matched families**: **68 / 68** verified Hyperliquid first-party struct families (0 third-party `alloy`/`revm`/`reth` structs, 0 `core`/`alloc`/`std`, 0 `drop_in_place`)
- **Anchor mode**: **100% `rodata`** (`190w / 87,914 B` direct PC32 `.rodata` field-name authentication)
- **Matched across 16 first-party components**:

| Component | Windows | Bytes |
|---|---:|---:|
| `consensus` | 52 | 27,726 |
| `staking` | 24 | 12,575 |
| `risk` | 27 | 10,370 |
| `fees` | 15 | 7,665 |
| `orderbook` | 14 | 6,451 |
| `dex-registry` | 17 | 6,308 |
| `abci` | 11 | 4,102 |
| `assets` | 9 | 3,528 |
| `evm` | 5 | 2,897 |
| `foundation` | 4 | 2,045 |
| `exchange` | 4 | 1,172 |
| `vaults` | 2 | 899 |
| `bridge` | 2 | 652 |
| `action-wire` | 2 | 646 |
| `node-runtime` | 1 | 552 |
| `transport` | 1 | 326 |
| **Total** | **190** | **87,914** |

## Strict Admission & Hygiene Gates

1. `#![forbid(unsafe_code)]` Rust source (`harness/src/main.rs`) built strictly offline with `--offline --locked`.
2. Harness-only CGUs (`hl_node115_serialize_wave2_census-*.rcgu.o`, excluding `.rcgu.o.rcgu.o`) and harness-only `serde_core::ser::Serialize::serialize` symbols (`SerStructFam*`); zero `core::`/`alloc::`/`std::`/third-party attribution and zero `drop_in_place`.
3. Complete `.eh_frame` `.text` FDE boundaries, `size >= 24`, `relocation_bytes * 2 <= size`, `unmasked >= 12`, and `100.00%` relocation-qualified via `tools/byte_progress.compare` (0 relaxations).
4. Exact `.rodata` field-name anchor authentication (`>= min(expected_count, 2)` distinct expected field strings per FDE).
5. Zero overlaps across `start`/`end` and `start_va`/`end_va` against `research/byte-windows.json` and all committed sibling packets (including Slice 26 `RE-001-node115-first-party-serialize-census`).

## Verification

```sh
(cd research/work-items/RE-001-node115-first-party-serialize-wave2-census && sha256sum -c MANIFEST.sha256)
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-001-node115-first-party-serialize-wave2-census/census.py --rebuild --self-test
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_first_party_serialize_wave2_census_115 -v
```
