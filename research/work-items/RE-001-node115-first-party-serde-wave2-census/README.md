# RE-001: node115 First-Party `serde::Deserialize` ThinLTO Wave 2 Census

- Components: 14 first-party components (zero dependency credit; zero third-party alloy/revm families; zero short 1-2 char ambiguous keys)
- Target: node #115 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Toolchain: `rustc 1.95.0 (59807616e 2026-04-14)`, `x86_64-unknown-linux-gnu`,
  `opt-level = 3`, `overflow-checks = true`, `lto = "thin"`,
  `#[global_allocator] tikv-jemallocator = "=0.6.0"`, `serde = "=1.0.229"`,
  `serde_json = "=1.0.154"`, `rmp-serde = "=1.3.0"`
- Claim status: observation (static parsing + `#![forbid(unsafe_code)]` clean-room Rust ThinLTO build; no target execution)

## Summary

Extends `RE-001-node115-first-party-serde-thinlto-census` (`dea85b54c`, 56 families /
162w / 166,298 B) across **62 additional audited, unambiguously Hyperliquid
first-party `#[derive(serde::Deserialize)]` enum & `#[serde(deny_unknown_fields)]`
struct families** (`20` enums + `42` structs, excluding all third-party `alloy`/`revm`
families and all short 1-2 char generic field tables).

Admits **190 strictly disjoint, 100% relocation-qualified first-party `.text`
FDE windows (+69,261 bytes)** across **14 components** (`node115-fp-serde2-*`),
each independently anchored by exact `.rela.dyn` -> `.data.rel.ro` -> `.rodata`
`&[&str]` slice-table proof and verified zero-overlap against `research/byte-windows.json`
and all sibling packets:

| Component | Windows | Bytes |
| --- | ---: | ---: |
| `risk` | 38 | 13,640 |
| `bridge` | 15 | 8,445 |
| `dex-registry` | 15 | 7,086 |
| `vaults` | 18 | 6,954 |
| `action-wire` | 18 | 6,507 |
| `orderbook` | 21 | 6,468 |
| `assets` | 15 | 4,014 |
| `evm` | 17 | 3,670 |
| `exchange` | 6 | 3,228 |
| `fees` | 8 | 2,538 |
| `staking` | 6 | 2,013 |
| `consensus` | 6 | 1,896 |
| `constants` | 4 | 1,620 |
| `abci` | 3 | 1,182 |
| **Total** | **190** | **69,261** |

## Reproduce & Verify

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-001-node115-first-party-serde-wave2-census/census.py --verify
(cd research/work-items/RE-001-node115-first-party-serde-wave2-census && sha256sum -c MANIFEST.sha256)
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_first_party_serde_wave2_census_115 -v
```
