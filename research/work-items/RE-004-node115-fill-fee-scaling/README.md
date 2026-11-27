# RE-004: node #115 fill-fee scaling & HIP-3 deployer scale settlement pipeline (`0x44896f0`)

- Component ID: `fees` (`RE-004`)
- Target release and full SHA-256: Linux x86-64 node #115, `artifacts/node/115/hl-node`,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Claim status: observation for all `.rodata` float constants, integer clamp immediates, and call-site order in `0x44896f0`; inference for Rust domain names (`compute_fill_fee_triple`, `settle_fill_fee`). Complements `RE-004-node115-fee-scaling` and `fees-credit-distribution-115` with independently authored Rust in `src/node115-fees/src/credit.rs`.

## Evidence (node #115 static observations)

| VA / Immediate | Observed #115 value / role |
| --- | --- |
| `.rodata` `0x4592b0` | `1.0_f64` (`HIP3_DEFAULT_SCALE_CAP`, loaded at `0x448976d`, `0x4489795`, `0x44897ce`) |
| `.rodata` `0x4593d0` | `5.0_f64` (`HIP3_NON_GROWTH_RAW_SCALE`, loaded at `0x44897c3`) |
| `.rodata` `0x4593e0` | `0.1_f64` (`HIP3_NON_GROWTH_FACTOR`, loaded at `0x44897df`) |
| `0x4489847` | `0x028f5c28f5c28f5c` (`i64::MAX / 50`, pre-scaling input cap) |
| `0x4489858` / `0x44898ee` | `±0x0147ae147ae147ae` (`±i64::MAX / 100`, pre-x100 signed clamp) |
| `0x4489912` | `0x346dc5d63886594b` (`>> 11` = unsigned `/ 10_000`) |
| `0x4489b34`, `0x4489b71`, `0x4489d52`, `0x4489d83` | `side_kind == 2` early skip; otherwise `extra_credit (0x3c1a3f0)` -> `scale_x100 (0x46a6860)` -> `distribute (0x3c1ae50)` |

## Reproduce

```sh
python3 tools/artifacts.py verify
python3 -m unittest tests.test_fill_fee_scaling_115
CARGO_BUILD_JOBS=4 RUST_TEST_THREADS=4 CARGO_TARGET_DIR=work/target/assets-fees-book \
  cargo test --offline --locked --manifest-path src/node115-fees/Cargo.toml
(cd research/work-items/RE-004-node115-fill-fee-scaling && sha256sum -c MANIFEST.sha256)
```
