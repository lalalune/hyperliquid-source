# RE-015: Node #115 `global_constants` 100% First-Party CGU Compiled-Byte Identity (`home_dir` + `read_aws_name`)

## Target & Provenance

- **Target binary**: `artifacts/node/115/hl-node` (`105,896,032` bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`)
- **Compiler & profile**: `rustc 1.95.0 (59807616e 2026-04-14)`, `--edition=2021`, `opt-level = 3`, `lto = "thin"`, `overflow-checks = true`, `#[global_allocator]` = `tikv-jemallocator 0.6.0`, unmodified offline crates.io `serde 1.0.229 (derive)` + `serde_json 1.0.154 (raw_value, unbounded_depth)`
- **Verification mode**: Live offline ThinLTO rebuild (`verify.py --rebuild --self-test`) checked with `tools/byte_progress.py::compare` (4-byte PC32/PLT32/GOTPCREL displacement relocations only; zero relaxations, zero non-relocation byte diffs)

## New Strictly Disjoint First-Party Windows (+2 FDEs / +682 B)

| VA Range | Size | Raw-Equal | Reloc Bytes | Non-Reloc Diffs | Attribution | Symbol |
| --- | ---: | ---: | ---: | ---: | --- | --- |
| `0x17782e0..0x17783dd` | `253 B` | `221 B` | `32 B` | `0` | `first_party_logic` | `global_constants::static_config::home_dir` |
| `0x17783e0..0x177858d` | `429 B` | `375 B` | `60 B` | `0` | `first_party_logic` | `global_constants::static_config::read_aws_name` |
| **Total** | **`682 B`** | **`596 B` (`87.39%`)** | **`92 B`** | **`0`** | **100% first-party** | **2/2 relocation-qualified** |

### Recovered Idioms That Closed the Final Two First-Party Functions

1. **`global_constants::static_config::home_dir` (`0x17782e0`, `253/253 B`, 0 non-reloc diffs)**:
   - Uses an inner `?`-returning helper (`fn inner() -> Option<String> { let p = std::env::home_dir()?; Some(p.to_str()?.to_string()) } inner().unwrap_or_default()`), which allows LLVM StackColoring to reuse the single 24-byte slot `0(%rsp)` (`subq $0x18, %rsp`) across `std::env::home_dir()` and `core::str::converts::from_utf8`, drop `PathBuf` before the shared `String` return write at `0x177838e`, and keep the `Err` and empty-string paths structurally exact.
   - Synced into `src/global-constants/src/static_config.rs` (zero external dependencies, `#![forbid(unsafe_code)]`).
2. **`global_constants::static_config::read_aws_name` (`0x17783e0`, `429/429 B`, 0 non-reloc diffs)**:
   - Uses `fs::read_to_string(&path).ok().and_then(|c| serde_json::from_str::<file_repr::StaticConfig>(&c).ok()).map(|cfg| cfg.aws_name).unwrap_or(AwsName::NvTestnet)`, which reuses `0x18(%rsp)` across `format!("{code_dir}/static_config")` and `fs::read_to_string::inner` (`subq $0x58, %rsp`) and reproduces the exact drop order (`drop(serde_json::Error)` -> `drop(contents)` -> `cmovel` `AwsName::NvTestnet` (`0x21`) -> `drop(path)`).

## Complete `global_constants` CGU & Full-Scope Location Audit

- **First-party `global_constants` CGU FDEs**: **`12/12` (`12,753 / 12,753 B = 100.00%`)** reproduced simultaneously in this single unmodified offline build (`aws_name_path`, `AwsName::deserialize`, `read_aws_name_fallback`, `AwsName::__FieldVisitor::visit_str`, `VariantNotFound::fmt`, `AwsName::fmt`, `AwsName::from_str`, `cham_dir`, `cham_dir::{{closure}}`, `home_dir`, `read_aws_name`, `new_static_config`).
- **Entire `global_constants` CGU (`0x1772f80..0x1778ad7`, `40` FDEs / `23,050 B`)**: **`38/40` (`22,877 / 23,050 B = 99.25%`)** reproduced simultaneously in this single unmodified build (all 36 previously matched CGU FDEs + these 2 new first-party FDEs).
- **All `5/5` `.data.rel.ro` `Location` records referencing `global_constants/` verified**:
  - `0x64111d8` (`aws_name.rs:295:44`), `0x64111f0` (`aws_name.rs:295:68`), `0x6411420` (`static_config.rs:61:17`), `0x6411438` (`static_config.rs:24:9`): all `3/3` in-CGU FDEs (`0x1773fd0`, `0x1778270`, `0x17785f0`) are 100% matched.
  - `0x6411208` (`aws_name.rs:213:29`, `unimplemented!()`): inlined into cross-CGU caller `0x2e11b00..0x2e13c3a` (`8,506 B`, outside the `global_constants` CGU).
- **Residual `2/40` third-party `serde_json` CGU FDEs (`173 B = 0.75%`) — honestly kept unmatched**:
  - `0x1775ee0..0x1775f46` (`102 B`, `serde_json::Deserializer::peek_error`) and `0x1776c20..0x1776c67` (`71 B`, `serde_json::Deserializer::error`).
  - Root cause proven from `.data.rel.ro` Locations `0x64c2450..0x64c24e0` (`/home/ubuntu/hl/code_Mainnet/z_vendor/serde_json/src/read.rs:{422,427,428,580}`): node #115 vendors `serde_json` (`1.0.145..1.0.149` era: `1.0.140` `read.rs` + `1.0.145+` `de.rs` `MapKey` fix) paired with `memchr 2.7.x` (before `memchr 2.8.x` added `unreachable_unchecked()` in `search_slice_with_raw`), keeping `SliceRead::position_of_index` (`0x5c56920`, `184 B`) out-of-line with LLVM `ArgumentPromotion`. Because the offline crates.io cache carries unmodified `memchr 2.8.3` and `serde_json 1.0.140`/`1.0.154`, we do **not** patch registry crates to claim those two third-party FDEs, and we keep `identity_gate_satisfied: false` honestly per `docs/SCOPE.md`.

## Verification Commands

```bash
cd research/work-items/RE-015-node115-constants-first-party-100pct-byte-matches && sha256sum -c MANIFEST.sha256
PYTHONDONTWRITEBYTECODE=1 CARGO_BUILD_JOBS=4 python3 research/work-items/RE-015-node115-constants-first-party-100pct-byte-matches/verify.py --rebuild --self-test
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_constants_first_party_100pct_115 tests.test_constants_thinlto_byte_matches_115 tests.test_global_constants_115 -v
```
