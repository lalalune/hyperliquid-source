# RE-001: Node #115 First-Party `serde::Serialize` ThinLTO Census

- **Task**: `RE-001` (first-party compiled-byte reconstruction)
- **Target**: `artifacts/node/115/hl-node` (Linux x86-64 ELF, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`)
- **Toolchain**: `rustc 1.95.0 (59807616e 2026-04-14)`, `opt-level = 3`, `overflow-checks = true`, `lto = "thin"`, `tikv-jemallocator = "=0.6.0"`, `serde = "=1.0.229"`, `serde_json = "=1.0.140"`, `rmp-serde = "=1.3.0"`
- **Consolidation prefix**: `node115-fp-ser-*`

## Summary

This work-item packet opens the **first-party `serde::Serialize`** compiled-byte vein across `serde_json` (`CompactFormatter` / `PrettyFormatter` / `Value`) and `rmp-serde` (MessagePack `DefaultConfig` / `StructMapConfig` / `HumanReadableConfig` / `BinaryConfig`) for verified Hyperliquid first-party enum and struct families (`family_meta.json`).

Two key compiler-provenance findings unlocked this vein:
1. **`serde_json` `format_escaped_str` inlining trigger**: Node #115 links a `serde_json 1.0.140`–era `format_escaped_str_contents` implementation and calls `Serializer::collect_str` (a second caller of `format_escaped_str_contents`), which keeps `format_escaped_str_contents` out-of-line and allows LLVM to inline `format_escaped_str` directly into `<T as serde::Serialize>::serialize`. Reproducing this with `CollectStrTrigger` and pinned function-pointer instantiations (`pin_ser`) under `serde_json = "=1.0.140"` yields exact byte-for-byte relocation-qualified matches for `serde_json` serializers alongside `rmp-serde` serializers.
2. **Dual-mode cryptographic string authentication**: Every admitted node #115 FDE is authenticated against expected Hyperliquid variant/field UTF-8 strings either via direct PC32 `.rodata`/`.data.rel.ro` relocations (`rodata`: 112 windows / 39,052 B; `rodata+inline_ascii`: 9 windows / 8,547 B) or via literal unmasked UTF-8 immediate bytes constant-folded by LLVM into `rmp_serde` `Vec<u8>` fast-path instructions (`inline_ascii`: 37 windows / 20,771 B).

### Verified Yield

- **Total matched windows**: **158** complete `.eh_frame` `.text` FDEs (**`68,370 B`**, **100.00% relocation-qualified** via `tools/byte_progress.compare` with 0 relaxations, 0 overlaps internally, with `research/byte-windows.json`, or with any committed sibling packet)
- **By family kind**: `151` enum FDEs (`66,299 B`) + `7` struct FDEs (`2,071 B`) across **31** distinct verified Hyperliquid families
- **By anchor mode**: `rodata` (`112w / 39,052 B`), `inline_ascii` (`37w / 20,771 B`), `rodata+inline_ascii` (`9w / 8,547 B`)
- **Matched across 10 first-party components**:

| Component | Windows | Bytes |
|---|---:|---:|
| `risk` | 53 | 18,978 |
| `dex-registry` | 32 | 18,045 |
| `orderbook` | 19 | 10,337 |
| `action-wire` | 24 | 8,018 |
| `exchange` | 10 | 3,917 |
| `constants` | 7 | 3,611 |
| `bridge` | 5 | 2,805 |
| `staking` | 5 | 1,530 |
| `fees` | 2 | 568 |
| `consensus` | 1 | 561 |
| **Total** | **158** | **68,370** |

## Strict Admission & Hygiene Gates

1. `#![forbid(unsafe_code)]` Rust source (`harness/src/main.rs`) built strictly offline with `--offline --locked` (`harness/Cargo.lock`, SHA-256 `d1c342d118a5095284e83b9fd723e815126fe18494906e29373fec47ceb1331a`).
2. Harness-only CGUs (`hl_node115_serialize_census-*.rcgu.o`, excluding `.rcgu.o.rcgu.o`) and harness-only `serde_core::ser::Serialize::serialize` symbols (`SerEnumFam*` / `SerStructFam*`); zero `core::`/`alloc::`/`std::`/third-party attribution and zero `drop_in_place`.
3. Complete `.eh_frame` `.text` FDE boundaries, `size >= 24`, `relocation_bytes * 2 <= size`, `unmasked >= 12`, and `100.00%` relocation-qualified via `tools/byte_progress.compare` (0 relaxations).
4. Dual-mode variant/field UTF-8 anchor authentication (`>= min(expected_count, 2)` distinct expected strings per FDE).
5. Zero overlaps across `start`/`end` and `start_va`/`end_va` against `research/byte-windows.json` and all committed sibling packets.

## Verification

```sh
(cd research/work-items/RE-001-node115-first-party-serialize-census && sha256sum -c MANIFEST.sha256)
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-001-node115-first-party-serialize-census/census.py --rebuild --self-test
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_first_party_serialize_census_115 -v
```
