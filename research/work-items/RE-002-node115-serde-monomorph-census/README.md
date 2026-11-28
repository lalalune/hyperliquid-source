# RE-002 — Node #115 `serde 1.0.229` Monomorphization Census (`node115-serde-mono-*`)

Relocation-qualified byte census of unmodified crates.io `serde 1.0.229` (`serde::private::de::content::EnumDeserializer<E>::variant_seed`) monomorphizations compiled under the node #115 ThinLTO + `tikv-jemallocator` toolchain (`rustc 1.95.0 (59807616e 2026-04-14)`, `x86_64-unknown-linux-gnu`, `opt-level = 3`, `overflow-checks = true`, `lto = "thin"`, `tikv-jemallocator = "=0.6.0"`, `serde = "=1.0.229"`, `serde_json = "=1.0.140"`, `rmp-serde = "=1.3.0"`).

## Scope & Attribution Policy

- **Target**: `artifacts/node/115/hl-node` (`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).
- **Attribution**: Strictly **dependency-tagged (`vendored-crates:serde`, zero first-party credit)**. Every admitted symbol is strictly `serde::private::de::content::EnumDeserializer<E>::variant_seed` from unmodified crates.io `serde 1.0.229` (`MIT OR Apache-2.0`, recorded in `licenses.json`).
- **Disjointness**: 0 internal overlaps, 0 overlaps with `research/byte-windows.json`, and 0 overlaps across all sibling peer packets.

## Summary

| Metric | Value |
| --- | ---: |
| Admitted FDE windows | **147** |
| Total `.text` bytes | **127,415 B** (`0.1522%` of node #115 `.text`) |
| FDE size range | `670 B` – `1,095 B` |
| Raw-equal windows | `0` |
| Relaxed windows | `0` (`100%` strict relocation-qualified via `tools/byte_progress.py::compare`) |
| Unique `.data.rel.ro` `&[&str]` slice-table families | **28** |
| Dependency / crate | `vendored-crates:serde` (`1.0.229`, `MIT OR Apache-2.0`) |

## Adversarial Qualification Gates

Every record in `census.json` is independently verified by `census.py --verify` and `tests/test_serde_monomorph_census_115.py`:

1. Exact complete `.eh_frame` `.text` FDE extent (`length >= 32 B`), relocation-masked bytes `<= length / 2`, zero relaxations, `100%` relocation-qualified via `tools/byte_progress.py::compare`.
2. Defining symbol strictly under `serde::private::de::content::*` (`variant_seed`), excluding all harness symbols (`hl_node115_serde_w4_census`) and all `drop_in_place` glue.
3. Exact `.rela.dyn -> .data.rel.ro -> .rodata &[&str]` slice-table proof: a PC32 relocation inside the node #115 FDE resolves to `table_va` in `.data.rel.ro` whose runtime pointers (via `.rela.dyn` `R_X86_64_RELATIVE`) and lengths match the exact ordered variant string list in node #115 `.rodata`.
4. Permissive license proof (`licenses.json`) and locked crates.io checksum (`harness/Cargo.lock`).

## Reproducibility & Verification

```bash
# Re-verify committed packet against artifacts/node/115/hl-node
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-002-node115-serde-monomorph-census/census.py --verify

# Verify packet SHA-256 manifest
(cd research/work-items/RE-002-node115-serde-monomorph-census && sha256sum -c MANIFEST.sha256)

# Run unit tests & negative controls
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_serde_monomorph_census_115 -v
```
