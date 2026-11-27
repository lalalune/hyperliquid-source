# RE-015: Node #115 `constants` (`global_constants`) ThinLTO + `tikv-jemallocator` CGU Byte Identity (36/40 FDEs, 96.29%)

- **Component ID**: `constants` (Stream F, `RE-015`, following `#263` / `#268` / `56d71e9f3`)
- **Target Artifact**: `artifacts/node/115/hl-node` (Linux x86-64 ELF, 105,896,032 bytes)
- **Target SHA-256**: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- **Compiler Profile (exact node #115 match)**:
  - `rustc 1.95.0 (59807616e 2026-04-14)`
  - `[profile.release]`: `opt-level = 3`, `lto = "thin"`, `overflow-checks = true` (default baseline `x86_64-unknown-linux-gnu` target CPU, zero custom `RUSTFLAGS` other than `-C save-temps` for object extraction)
  - Workspace structure: `global_constants` library crate (`serde = "=1.0.229"` `["derive"]`, `serde_json = "=1.0.154"` `["raw_value", "unbounded_depth"]`) depended on by binary crate with `#[global_allocator] tikv_jemallocator::Jemalloc` (`tikv-jemallocator = "=0.6.0"`).
- **Claim Status**: Static compilation and ELF comparison only (captured binaries are never executed). No `research/progress.json` gates are modified by this packet. All 22 new windows are strictly disjoint from `research/byte-windows.json` (Wave 3) and all sibling `*-byte-matches*` / `constants-gate-closure` packets.

## Compiler Profile Discovery & CGU Coverage Jump

Combining `lto = "thin"` + `#[global_allocator] tikv-jemallocator 0.6.0` + `serde_json 1.0.154` with `features = ["raw_value", "unbounded_depth"]` (proven by `cmpb $0, 0x48(%rsi); movzbl 0x49(%rsi), %ecx` at `0x1773118` inside `0x1773070`) in a separate `global_constants` library crate reproduces **36 / 40 FDEs (`22,195 / 23,050 B = 96.29%`)** of the entire `global_constants` CGU (`0x1772f80..0x1778ad7`) at **100.00% relocation-qualified byte identity (0 non-relocation byte mismatches)** in a single build:

- **14 FDEs (`7,841 B`)** already covered by `research/byte-windows.json` (`0x1774100`, 2,785 B), `RE-015-node115-stream-f-byte-matches` (`0x17785d0`, 25 B), and `RE-015-node115-constants-gate-closure` (`12` FDEs, 5,031 B) — all 14 are also reproduced verbatim by this build.
- **22 brand-new, strictly disjoint CGU FDEs (`14,354 B`, `13,452 / 14,354 = 93.72%` raw-equal, 0 non-relocation diffs)** recorded in `records.json` + `bodies.bin`:
  - **5 first-party `global_constants` functions (`5,231 B`, `4,959/5,231 = 94.80%` raw-equal)**:
    - `0x1773070..0x1773fc4` (`3,924 B`, `3,872/3,924` raw-equal): `AwsName::deserialize` (`#[derive(Deserialize)]`)
    - `0x17780c0..0x1778265` (`421 B`, `370/421` raw-equal): `global_constants::static_config::cham_dir`
    - `0x17785f0..0x177876f` (`383 B`, `322/383` raw-equal): `global_constants::static_config::StaticConfig::new`
    - `0x1773fd0..0x17740fe` (`302 B`, `234/302` raw-equal): `global_constants::aws_name::read_aws_name_fallback`
    - `0x1772fa0..0x1773069` (`201 B`, `161/201` raw-equal): `global_constants::aws_name::aws_name_path`
  - **17 CGU-monomorphized `serde_json` / `serde_core` / jemalloc `drop_in_place` routines (`9,123 B`, `8,493/9,123 = 93.09%` raw-equal)**:
    - `0x17771b0..0x1777faf` (`3,583 B`, `3,348/3,583` raw-equal): `serde_json::Deserializer::deserialize_ignored_any`
    - `0x1775f50..0x1776292` (`834 B`), `0x1776910..0x1776c17` (`775 B`), `0x1776680..0x1776908` (`648 B`), `0x1776430..0x177667a` (`586 B`), `0x17762a0..0x1776427` (`391 B`), `0x1776dc0..0x1776f41` (`385 B`), `0x1776f50..0x177707a` (`298 B`), `0x1777080..0x17771a3` (`291 B`), `0x1775dd0..0x1775ede` (`270 B`), `0x1776cc0..0x1776db2` (`242 B`), `0x1774cf0..0x1774dc1` (`209 B`), `0x1778770..0x177883e` (`206 B`), `0x1777fd0..0x177805b` (`139 B`), `0x1774dd0..0x1774e37` (`103 B`), `0x1778060..0x17780b5` (`85 B`), `0x1776c70..0x1776cbe` (`78 B`).
- **Remaining 4 / 40 CGU FDEs (`855 B = 3.71%`)**: honestly left unmatched in this packet:
  - `0x17782e0..0x17783dd` (`253 B`, `home_dir`) & `0x17783e0..0x177858d` (`429 B`, `read_aws_name`): identical control flow and semantics, minor LLVM stack-slot coloring delta (`258 B`/`417 B` vs `253 B`/`429 B`).
  - `0x1775ee0..0x1775f46` (`102 B`, `serde_json::Deserializer::peek_error`) & `0x1776c20..0x1776c67` (`71 B`, `serde_json::Deserializer::error`): node #115 did not ThinLTO-inline `SliceRead::position_of_index` (`0x5c56920`, `184 B`), whereas the 2-crate probe imports it under default `-import-instr-limit=100`.

## Reproduce

```sh
# Fast offline verification of committed compiled bodies against node #115 ELF:
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-015-node115-constants-thinlto-byte-matches/verify.py --self-test

# Full live ThinLTO + tikv-jemallocator rebuild verification (uses local ~/.cargo cache):
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-015-node115-constants-thinlto-byte-matches/verify.py --rebuild --self-test

PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_constants_thinlto_byte_matches_115 -v
(cd research/work-items/RE-015-node115-constants-thinlto-byte-matches && sha256sum -c MANIFEST.sha256)
```
