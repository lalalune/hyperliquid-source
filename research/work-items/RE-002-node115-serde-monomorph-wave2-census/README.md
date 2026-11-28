# RE-002 — Node #115 `serde_json 1.0.154` Monomorphization Wave 2 Census (`node115-serde-mono2-*`)

Relocation-qualified byte census of unmodified crates.io `serde_json 1.0.154` (`<serde_json::de::VariantAccess<R> as EnumAccess>::variant_seed` and `<serde_json::de::UnitVariantAccess<R> as EnumAccess>::variant_seed`) monomorphizations compiled under the node #115 ThinLTO + `tikv-jemallocator` toolchain (`rustc 1.95.0 (59807616e 2026-04-14)`, `x86_64-unknown-linux-gnu`, `opt-level = 3`, `overflow-checks = true`, `lto = "thin"`, `tikv-jemallocator = "=0.6.0"`, `serde = "=1.0.229"`, `serde_json = "=1.0.154"`, `rmp-serde = "=1.3.0"`).

## Scope & Attribution Policy

- **Target**: `artifacts/node/115/hl-node` (`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).
- **Attribution**: Strictly **dependency-tagged (`vendored-crates:serde_json`, zero first-party credit)**. Every admitted symbol is strictly `<serde_json::de::{VariantAccess,UnitVariantAccess}<R> as serde_core::de::EnumAccess>::variant_seed` from unmodified crates.io `serde_json 1.0.154` (`MIT OR Apache-2.0`, recorded in `licenses.json`).
- **Disjointness**: 0 internal overlaps, 0 overlaps with live Wave-8 `research/byte-windows.json`, and 0 overlaps across all sibling peer packets (including `RE-002-node115-serde-monomorph-census` and `RE-002-node115-rust-vendor-wave6-census`).

## Summary

| Metric | Value |
| --- | ---: |
| Admitted FDE windows | **139** |
| Total `.text` bytes | **52,780 B** (`0.0630%` of node #115 `.text`) |
| `VariantAccess::variant_seed` | `68` windows / `29,756 B` |
| `UnitVariantAccess::variant_seed` | `71` windows / `23,024 B` |
| Raw-equal windows | `0` |
| Relaxed windows | `0` (`100%` strict relocation-qualified via `tools/byte_progress.py::compare`) |
| Unique `.data.rel.ro` `&[&str]` slice-table families | **36** |
| Dependency / crate | `vendored-crates:serde_json` (`1.0.154`, `MIT OR Apache-2.0`) |

## Adversarial Qualification Gates

Every record in `census.json` is independently verified by `census.py --verify` and `tests/test_serde_monomorph_wave2_census_115.py`:

1. Exact complete `.eh_frame` `.text` FDE extent (`length >= 32 B`), relocation-masked bytes `<= length / 2`, zero relaxations, `100%` relocation-qualified via `tools/byte_progress.py::compare`.
2. Defining symbol strictly under `serde_json::de::{VariantAccess,UnitVariantAccess}::variant_seed`, excluding all harness symbols (`hl_mono_w2_*`), `drop_in_place` glue, and stdlib symbols.
3. Exact `.rela.dyn -> .data.rel.ro -> .rodata &[&str]` slice-table proof: a PC32 relocation inside the node #115 FDE resolves to `table_va` in `.data.rel.ro` whose runtime pointers (via `.rela.dyn` `R_X86_64_RELATIVE`) and lengths match the exact ordered variant string list in node #115 `.rodata`.
4. Permissive license proof (`licenses.json`) and locked crates.io checksums (`w2_e{0,1,2}/Cargo.lock`).

## Reproducibility & Verification

```bash
# Re-verify committed packet against artifacts/node/115/hl-node
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-002-node115-serde-monomorph-wave2-census/census.py --verify

# Verify packet SHA-256 manifest
(cd research/work-items/RE-002-node115-serde-monomorph-wave2-census && sha256sum -c MANIFEST.sha256)

# Run unit tests & negative controls
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_serde_monomorph_wave2_census_115 -v
```
