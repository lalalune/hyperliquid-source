# Node #115 First-Party Byte-Comparison Census Crate

Independently authored, dependency-free, `#![forbid(unsafe_code)]` Rust implementations
of bounded first-party functions observed in Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

When compiled with the target's observed compiler (`rustc 1.95.0 (59807616e 2026-04-14)`,
`--edition=2021 -C opt-level=3 -C overflow-checks=yes`), each exported function compiles to
exact raw-equal or relocation-qualified x86-64 machine code matching its corresponding
complete FDE window(s) in `artifacts/node/115/hl-node`.

## Scope and limitations

- Covers 14 Hyperliquid enum wire-name `visit_str` codecs (`ChainName`, `SpotMarkKind`,
  `Tif`, `OutcomeKind`, `MarginMode`, `Operation`, `BorrowLendField`, `BridgeEvent`,
  `DisabledState`, `EvmTxType`, `ReadPrecompileOutcomeName`, `AbstractionKind`,
  `VoteChoice`, `ProposalCategory`) and 5 leaf helpers (`slice20_equal`, `fee_window_scan`,
  `sub256_borrow`, `bounded_offset`, `two_span_projection`).
- Error return shapes (`RmpErr` and `JsonErr`) model the observed `serde` error ABI
  layouts (`rmp_serde::decode::Error` 9-variant niche tag `0x09` and `serde_json::Error`
  boxed payload) without external crates; relocation fields (`PC32`/`PLT32`/`GOTPCREL`)
  are masked by `tools/byte_progress.py` and not resolved to linked symbols.
- Does not close any full-component gate in `research/progress.json` or claim whole-ELF
  equivalence.

## Verification

```sh
CARGO_BUILD_JOBS=4 RUST_TEST_THREADS=4 \
  CARGO_TARGET_DIR=work/target/first-party-byte-census \
  cargo +1.95.0 test --offline --locked --manifest-path src/node115-first-party-byte-census/Cargo.toml
python3 research/work-items/RE-001-node115-first-party-byte-census/census.py --verify
```
