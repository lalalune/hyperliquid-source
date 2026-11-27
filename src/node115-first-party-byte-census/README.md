# `node115-first-party-byte-census`

Independently authored, dependency-free, `#![forbid(unsafe_code)]` Rust crate implementing
first-party node #115 functions for compiled-byte comparison against authenticated
`artifacts/node/115/hl-node` (`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).

## Scope & Wave 3 Coverage

Compiled with the exact node #115 Rust toolchain and profile (`rustc 1.95.0 (59807616e 2026-04-14)`,
`--edition=2021 --crate-type=rlib -C opt-level=3 -C overflow-checks=yes`), this crate reproduces
**1,008 authenticated first-party `.text` FDE windows (138,449 bytes, 127,869/138,449 = 92.36%
raw-equal, 1,008/1,008 = 100.00% relocation-qualified)** spanning **all 23/23 components** of
`research/components.json`:

- `src/lib.rs`: Leaf helpers (`slice20_equal`, `fee_window_scan`, `sub256_borrow`, `bounded_offset`,
  `two_span_projection`), Wave 1–2 enum `visit_str` codecs (`Action` 92-variant, `ShortActionTag`
  114-variant, `NodeEnv` 79-variant, `PerpDeploy` 16-variant+alias, `Hip3Star`, `ChainName`, `Tif`,
  `BridgeEvent`, `EvmTxType`, `AbstractionKind`, `VoteChoice`, `ProposalCategory`, etc.).
- `src/enums_wave3.rs`: 22 curated Hyperliquid enum `visit_str` codecs (`InfoRequest` 55-variant,
  `PerpDeployActionV2` 18-variant, `SpotDeployAction` 16-variant, `OutcomeDeployAction` 13-variant,
  `AgentAction`, `IndexedArtifactContentSerde`, `CValidatorAction`, `StakingLink`, `VaultRelationship`,
  `NodeStreamRole`, `QuorumStatus`, etc.).
- `src/fields_wave3.rs`: 33 curated Hyperliquid wire struct `FieldVisitor::visit_str` codecs across
  `action-wire`, `staking`, `vaults`, `fees`, `risk`, `bridge`, `dex-registry`, `orderbook`, `exchange`.
- `src/assets_wave3.rs`: 8 `l1/src/spot_meta.rs` and `l1/src/perp_meta.rs` business-logic FDEs
  (`TokenSpec::wei_per_sz`, `SpotMeta::{first_spot_for_token,spot_for_quote,quote_name_pair,checked_sz_to_wei}`,
  `PerpMeta::{px_decimals,sz_to_f64,px_to_f64}`).
- `src/expecting_wave3.rs`: Curated first-party `serde::de::Visitor::expecting` FDEs (25 B each,
  each verified both by relocation-qualified machine code and by exact `.rodata` string target
  resolution in `artifacts/node/115/hl-node`).

## Verification

```sh
CARGO_BUILD_JOBS=4 RUST_TEST_THREADS=4 CARGO_TARGET_DIR=work/target/fp-census \
  cargo +1.95.0 test --offline --locked --release --manifest-path src/node115-first-party-byte-census/Cargo.toml
CARGO_BUILD_JOBS=4 CARGO_TARGET_DIR=work/target/fp-census \
  cargo +1.95.0 clippy --offline --locked --manifest-path src/node115-first-party-byte-census/Cargo.toml --all-targets -- -D warnings
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-001-node115-first-party-byte-census/census.py --verify --rebuild
```
