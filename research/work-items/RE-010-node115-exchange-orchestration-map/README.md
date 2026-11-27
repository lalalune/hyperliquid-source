# RE-010: node #115 exchange orchestration source map & `stake_requirement` gate (`0x2c59480`, `0x2c58c70`, `0x294ceb0`)

- Component ID: `exchange` (`RE-010`)
- Target release and full SHA-256: Linux x86-64 node #115, `artifacts/node/115/hl-node`,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Claim status: **observation** for all 9 FDE extents, 4-arm jump table `0x60aeec`, 4x4 `.rodata` stake-requirement matrix `0x602d1c` (`0x457d00`/`0x457b00`/`0x457f00`), 2 outcome-deployer rejection strings (`0x7c8a97`, `0x7c8aae`), 8 instruction anchors, and all 15 distinct `l1/src/exchange/*.rs` source-file panic `Location` records (16 anchored entries); **inference** for reconstructed Rust API names (`StakeRequirement`, `Chain`, `check_stake_requirement`, `compute_total_required_stake`) implemented in `src/exchange/src/stake_requirement.rs`.
- Remaining unknowns: exact semantic label of the `Exchange+0x3968` 20-byte user set in `StakeRequirement` variant 2 (`0x2c58cee`, 500k HYPE on Mainnet/Sandbox) and full disassembly of `simulate_portfolio_margin.rs` (`0x644d900..0x644d960`) and `begin_block.rs` (`0x644d6d8..0x644d738`).

## Evidence (node #115 static observations)

### 1. `StakeRequirement` x `Chain` `.rodata` matrix (`0x602d1c`)

| Variant | Jump target (`0x60aeec`) | `.rodata` table | Local | Sandbox | Testnet | Mainnet |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| `0` (`Hip3PerpDex`) | `0x2c58c9f` -> `0x292deb0` | `0x457d00` | `100_000` (0.001 HYPE) | `10_000_000_000` (100 HYPE) | `10_000_000_000` (100 HYPE) | `50_000_000_000_000` (500,000 HYPE) |
| `1` (`SpotQuoteToken`) | `0x2c58e0f` | `0x457b00` | `50_000` (0.0005 HYPE) | `20_000_000_000_000` (200,000 HYPE) | `5_000_000_000` (50 HYPE) | `20_000_000_000_000` (200,000 HYPE) |
| `2` (`UserSetMembership`) | `0x2c58cee` | `0x457f00` | `200_000` (0.002 HYPE) | `50_000_000_000_000` (500,000 HYPE) | `10_000_000_000` (100 HYPE) | `50_000_000_000_000` (500,000 HYPE) |
| `3` (`OutcomeDeployer`) | `0x2c58dcd` -> `0x420e470` | `0x457d00` | `100_000` (0.001 HYPE) | `10_000_000_000` (100 HYPE) | `10_000_000_000` (100 HYPE) | `50_000_000_000_000` (500,000 HYPE) |

### 2. Core FDEs & Gate Constants

| Function VA (size) | Observed #115 behavior & anchors |
| --- | --- |
| `0x235a050..0x235a26e` (542 B) | Collects all 4 `StakeRequirement` amounts (`stake_requirement.rs:5:62`). |
| `0x294ceb0..0x294cfbe` (270 B) | Iterator `next()`: calls `0x2c58c70`, adds `+1` when `additional == Some(req)`, multiplies by `0x602d1c[req][chain]`; overflow writes error tag `0xc5` (`0x294cf9b`). |
| `0x2c58c70..0x2c59351` (1,761 B) | 4-arm jump table `0x60aeec` (`stake_requirement.rs:64:30`); arm 1 applies `0xf14280` s (183-day) disabled cooldown (`0x2c591a6`). |
| `0x292deb0..0x292dfee` (318 B) | Arm 0 HIP-3 perp DEX counter (`Exchange+0x7c8`/`+0x7d0`, stride `0x510`, `hip3_disabled_state` at `+0x468`: skips `3`, cooldown-checks `1` unless `is_override`, counts `0`/`2`). |
| `0x2c59360..0x2c59471` (273 B) | 183-day (`0xf14280` = `15_811_200` s) disabled-cooldown comparator against `Exchange.time` (`+0x60/+0x64/+0x68`). |
| `0x420e470..0x420e75d` (749 B) | Arm 3 active outcome deployer validator (`0x7c8a97`: `"not an outcome deployer"`, `0x7c8aae`: `"not an active outcome deployer"`, `0x1a2` on active). |
| `0x2c59480..0x2c5995b` (1,243 B) | `check_stake_requirement`: when `additional.is_some()`, checks disallowed account flag (`0x118` at `0x2c5956e`) and saturating account+sub-account value sum `<= 0x77359400` (`2_000_000_000`, `0x119` at `0x2c59674`), sums 4 variant stakes, queries `c_staking` (`Exchange+0xd88`, `0x64e7b50`), and writes `0x1a2` (`0x2c598e6`) or `0x11a` (`0x2c598f4`). |
| `0x2c71250..0x2c71ea5` (3,157 B) | `l1/src/exchange/end_block.rs:194:32` (`0x644d9a8`). |
| `0x2c77640..0x2c77ba5` (1,381 B) | `l1/src/exchange/impl_user.rs:195:40` (`0x644d9d8`). |

### 3. Complete `l1/src/exchange/*.rs` Source File Map (15 files)

Anchored via relocated `.data.rel.ro` panic `Location` records in `evidence.json`: `exchange.rs`, `begin_block.rs`, `end_block.rs`, `impl_global.rs`, `impl_bole.rs`, `impl_vault.rs`, `impl_outcome.rs`, `impl_outcome_deploy.rs`, `impl_trading.rs`, `impl_abstraction.rs`, `impl_spot_deploy.rs`, `stake_requirement.rs`, `simulate_portfolio_margin.rs`, `impl_user.rs`, `impl_ledger.rs`.

## Reproduce

```sh
python3 tools/artifacts.py verify
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_exchange_orchestration_map_115
PYTHONDONTWRITEBYTECODE=1 python3 tools/verify_packets.py research/work-items/RE-010-node115-exchange-orchestration-map
(cd research/work-items/RE-010-node115-exchange-orchestration-map && sha256sum -c MANIFEST.sha256)
CARGO_BUILD_JOBS=4 RUST_TEST_THREADS=4 CARGO_TARGET_DIR=work/target/risk-exchange \
  cargo test --offline --locked --manifest-path src/exchange/Cargo.toml
```
