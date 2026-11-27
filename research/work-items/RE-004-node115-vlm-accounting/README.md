# RE-004: node #115 cross-DEX/spot volume accounting (`raw_vlm.rs`, `scaled_vlm.rs`), fee monotonicity (`fees.rs:259`), and integrated `node115-fees` crate

- Component ID: `fees` (`RE-004`)
- Target release and full SHA-256: Linux x86-64 node #115, `artifacts/node/115/hl-node`,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Claim status: observation for all ELF FDE extents, `.rodata` privileged addresses, instruction encodings, and panic/overflow `Location` anchors; inference for Rust type names (`RawVlm`, `ScaledVlm`, `UserVolumeTotals`, `FeeLedger`, `FeeCell`, `FeeDistributionRecord`). No full-component acceptance gate is claimed by this packet alone.
- Implementation path: `src/node115-fees` (joins all 7 Cargo-packaged `fees` micro-crates + `node115-assets` + Rust implementations of `0x2a8b0a0`/`0x56195a0`/`0x543dc50`, `0x5495210`/`0x5495680`, `0x36e1b10`, `0x46a6860`, `0x3c1ae50`/`0x3c1a250`/`0x3c1a3f0`, and `0x3c10000` mode/tally rules).

## Evidence (node #115 static observations)

| VA / Range | Source diagnostic anchor | Observed #115 semantics |
| --- | --- | --- |
| `0x2a8b0a0` (576B FDE, previously unmapped) | `l1/src/raw_vlm.rs:17`, `l1/src/scaled_vlm.rs:16`, `l1/src/qtys/impl_ntl.rs:682` | Folds `(raw_vlm, scaled_vlm)` across all perp DEX clearinghouses (`exchange + 0x1338/0x1340`, stride `0x510`, user map `+0x60` via `0x4716be0`, user fields `+0x50`/`+0x58`, lazy default `0x64fda80`) plus the spot clearinghouse (`exchange + 0x3f0` via `0x4716cc0`, user fields `+0x40`/`+0x48`, lazy default `0x64fd958`); saturates both at `u64::MAX` reporting carries via `0x64e4ea8` (`0x6492e68` / `0x6483fe0`) |
| `0x56195a0` (672B FDE) | `l1/src/raw_vlm.rs:17`, `l1/src/scaled_vlm.rs:16` | Same cross-DEX + spot volume fold plus saturating add of an extra `raw_vlm` (`0x64aa3c8` overflow report) |
| `0x543dc50` (1200B FDE) | `l1/src/raw_vlm.rs:17`, `l1/src/scaled_vlm.rs:16` | Batch user-slice fold (stride `0x40`, user 20-byte key at `+0x18..+0x2c`) accumulating cross-DEX + spot `raw_vlm` with saturating add |
| `0x36e1b10` (128B FDE) | `l1/src/fees/fees.rs:259` | Iterates `windows(2)` over `f64` fee rates checking `ucomisd -0x8(%rdx), %xmm0; jbe` (monotonically non-increasing) |
| `0x46a6860` (368B FDE) | `l1/src/fees/compute.rs:45` | Checked `* 100` (`mov $0x64, %eax; mulq; jo`) on `gross`, `rebate`, optional `primary`, optional `secondary_total`, and `protocol` in exact order |
| `.rodata` 8 privileged addresses | `0x421a520` (`fees-open-order-threshold-115`) | 8 exact 20-byte addresses at `0x454410`, `0x454420`, `0x456c10`, `0x450d30`, `0x4513d0`, `0x453d70`, `0x455be0`, `0x454100` granted flat `10_000` open-order cap |

## Reproduce

```sh
python3 tools/artifacts.py verify
python3 -m unittest tests.test_fees_vlm_accounting_115
CARGO_BUILD_JOBS=4 RUST_TEST_THREADS=4 CARGO_TARGET_DIR=work/target/assets-fees-book \
  cargo test --manifest-path src/node115-fees/Cargo.toml
(cd research/work-items/RE-004-node115-vlm-accounting && sha256sum -c MANIFEST.sha256)
```
