# RE-001: Node #115 First-Party Compiled-Byte Comparison Census

- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source crate: `src/node115-first-party-byte-census/src/lib.rs` (SHA-256 `759ff01967ce2f272d8edd9b891fbb0c4cd0e8d5dd5ab3aec90937c21ed89740`)
- Compiler: `rustc 1.95.0 (59807616e 2026-04-14)` with `--edition=2021 --crate-type=rlib --crate-name=node115_first_party_byte_census -C opt-level=3 -C overflow-checks=yes --emit=obj`
- Scope: independently authored, dependency-free, `#![forbid(unsafe_code)]` Rust implementations compiled to exact raw-equal or relocation-qualified `.text` FDE matches. Static analysis and compilation only; no captured binary is executed.

## Summary

**66 authenticated first-party `.text` windows · 12,234 bytes compared · 11,359/12,234 (92.85%) raw-equal bytes · 6/66 raw-equal windows · 66/66 (100.00%) relocation-qualified · 12 components.**

| Component | Windows | Bytes | Raw-equal bytes | Raw-equal windows | Relocation-qualified |
| --- | ---: | ---: | ---: | ---: | ---: |
| `assets` | 3 | 147 | 147 (100.00%) | 3/3 | 3/3 |
| `bridge` | 5 | 1,764 | 1,527 (86.56%) | 0/5 | 5/5 |
| `consensus` | 8 | 1,403 | 1,341 (95.58%) | 0/8 | 8/8 |
| `constants` | 11 | 1,618 | 1,535 (94.87%) | 0/11 | 11/11 |
| `dex-registry` | 5 | 926 | 832 (89.85%) | 0/5 | 5/5 |
| `evm` | 6 | 1,110 | 1,062 (95.68%) | 0/6 | 6/6 |
| `exchange` | 5 | 1,520 | 1,382 (90.92%) | 0/5 | 5/5 |
| `fees` | 1 | 113 | 105 (92.92%) | 0/1 | 1/1 |
| `foundation` | 2 | 197 | 197 (100.00%) | 2/2 | 2/2 |
| `l1-shared` | 1 | 86 | 86 (100.00%) | 1/1 | 1/1 |
| `orderbook` | 5 | 1,197 | 1,123 (93.82%) | 0/5 | 5/5 |
| `risk` | 14 | 2,153 | 2,022 (93.92%) | 0/14 | 14/14 |

## Verified windows

| Component | ELF VA interval | Bytes | Raw-equal | Rels | Label | Anchor |
| --- | --- | ---: | ---: | ---: | --- | --- |
| `l1-shared` | `0x5436860..0x54368b6` | 86 | yes | 0 | l1/raw_signature_tracker slice20 equality (0x5436860) | `research/work-items/RE-001-node115-slice20-equal/README.md` |
| `fees` | `0x36e1b10..0x36e1b81` | 113 | 105/113 | 2 | l1/fees binary64 descending window scan (0x36e1b10) | `research/work-items/RE-004-fee-window-scan-115/README.md` |
| `assets` | `0x2ccdd80..0x2ccddb1` | 49 | yes | 0 | l1/qtys 256-bit unsigned subtraction with borrow (0x2ccdd80) | `research/work-items/RE-001-node115-sub256-borrow/README.md` |
| `assets` | `0x43be060..0x43be091` | 49 | yes | 0 | l1/qtys 256-bit unsigned subtraction with borrow (0x43be060) | `research/work-items/RE-001-node115-sub256-borrow/README.md` |
| `assets` | `0x564c830..0x564c861` | 49 | yes | 0 | l1/qtys 256-bit unsigned subtraction with borrow (0x564c830) | `research/work-items/RE-001-node115-sub256-borrow/README.md` |
| `foundation` | `0x45514d0..0x4551523` | 83 | yes | 0 | base VecDeque bounded ring offset search (0x45514d0) | `research/work-items/RE-001-node115-ring-offset/README.md` |
| `foundation` | `0x152e360..0x152e3d2` | 114 | yes | 0 | base VecDeque 80-byte two-span iterator (0x152e360) | `research/work-items/RE-001-node115-two-span-projection/README.md` |
| `constants` | `0x14be010..0x14be0a6` | 150 | 142/150 | 2 | global_constants ChainName RMP visit_str (0x14be010) | `research/work-items/RE-015-chain-codec-115/README.md` |
| `constants` | `0x2690cd0..0x2690d66` | 150 | 142/150 | 2 | global_constants ChainName RMP visit_str (0x2690cd0) | `research/work-items/RE-015-chain-codec-115/README.md` |
| `constants` | `0x4682610..0x46826a6` | 150 | 142/150 | 2 | global_constants ChainName RMP visit_str (0x4682610) | `research/work-items/RE-015-chain-codec-115/README.md` |
| `constants` | `0x57c3520..0x57c35b6` | 150 | 144/150 | 2 | global_constants ChainName RMP visit_str (0x57c3520) | `research/work-items/RE-015-chain-codec-115/README.md` |
| `constants` | `0x14be0b0..0x14be15c` | 172 | 165/172 | 2 | global_constants ChainName JSON visit_str (0x14be0b0) | `research/work-items/RE-015-chain-codec-115/README.md` |
| `constants` | `0x2690d70..0x2690e1c` | 172 | 165/172 | 2 | global_constants ChainName JSON visit_str (0x2690d70) | `research/work-items/RE-015-chain-codec-115/README.md` |
| `constants` | `0x46826b0..0x468275c` | 172 | 164/172 | 2 | global_constants ChainName JSON visit_str (0x46826b0) | `research/work-items/RE-015-chain-codec-115/README.md` |
| `constants` | `0x57c3470..0x57c351c` | 172 | 165/172 | 2 | global_constants ChainName JSON visit_str (0x57c3470) | `research/work-items/RE-015-chain-codec-115/README.md` |
| `constants` | `0x22e20d0..0x22e213e` | 110 | 102/110 | 2 | global_constants SpotMarkKind RMP visit_str (0x22e20d0) | `research/work-items/RE-015-spot-mark-codec-115/README.md` |
| `constants` | `0x3d47cb0..0x3d47d1e` | 110 | 102/110 | 2 | global_constants SpotMarkKind RMP visit_str (0x3d47cb0) | `research/work-items/RE-015-spot-mark-codec-115/README.md` |
| `constants` | `0x535bee0..0x535bf4e` | 110 | 102/110 | 2 | global_constants SpotMarkKind RMP visit_str (0x535bee0) | `research/work-items/RE-015-spot-mark-codec-115/README.md` |
| `orderbook` | `0x25cee60..0x25cef45` | 229 | 213/229 | 4 | l1/book Tif RMP visit_str (0x25cee60) | `src/node115-tif-name-codec/README.md` |
| `orderbook` | `0x4447430..0x4447515` | 229 | 215/229 | 4 | l1/book Tif RMP visit_str (0x4447430) | `src/node115-tif-name-codec/README.md` |
| `orderbook` | `0x5171260..0x5171345` | 229 | 213/229 | 4 | l1/book Tif RMP visit_str (0x5171260) | `src/node115-tif-name-codec/README.md` |
| `orderbook` | `0x25ced60..0x25cee5f` | 255 | 240/255 | 4 | l1/book Tif JSON visit_str (0x25ced60) | `src/node115-tif-name-codec/README.md` |
| `orderbook` | `0x4447330..0x444742f` | 255 | 242/255 | 4 | l1/book Tif JSON visit_str (0x4447330) | `src/node115-tif-name-codec/README.md` |
| `risk` | `0x25d3ca0..0x25d3d42` | 162 | 146/162 | 4 | l1/clearinghouse OutcomeKind RMP visit_str (0x25d3ca0) | `src/node115-oracle-outcome-kind/README.md` |
| `risk` | `0x44649e0..0x4464a82` | 162 | 146/162 | 4 | l1/clearinghouse OutcomeKind RMP visit_str (0x44649e0) | `src/node115-oracle-outcome-kind/README.md` |
| `risk` | `0x5479a10..0x5479ab2` | 162 | 146/162 | 4 | l1/clearinghouse OutcomeKind RMP visit_str (0x5479a10) | `src/node115-oracle-outcome-kind/README.md` |
| `risk` | `0x2868990..0x2868a20` | 144 | 136/144 | 2 | l1/clearinghouse MarginMode RMP visit_str (0x2868990) | `research/work-items/RE-007-margin-mode-codec-115/README.md` |
| `risk` | `0x3bcf9e0..0x3bcfa70` | 144 | 136/144 | 2 | l1/clearinghouse MarginMode RMP visit_str (0x3bcf9e0) | `research/work-items/RE-007-margin-mode-codec-115/README.md` |
| `risk` | `0x59fdec0..0x59fdf50` | 144 | 137/144 | 2 | l1/clearinghouse MarginMode RMP visit_str (0x59fdec0) | `research/work-items/RE-007-margin-mode-codec-115/README.md` |
| `risk` | `0x2691210..0x26912ac` | 156 | 148/156 | 2 | l1/bole Operation RMP visit_str (0x2691210) | `research/work-items/RE-007-borrow-lend-codec-115/README.md` |
| `risk` | `0x3d440a0..0x3d4413c` | 156 | 148/156 | 2 | l1/bole Operation RMP visit_str (0x3d440a0) | `research/work-items/RE-007-borrow-lend-codec-115/README.md` |
| `risk` | `0x57c3760..0x57c37fc` | 156 | 150/156 | 2 | l1/bole Operation RMP visit_str (0x57c3760) | `research/work-items/RE-007-borrow-lend-codec-115/README.md` |
| `risk` | `0x2691150..0x2691202` | 178 | 171/178 | 2 | l1/bole Operation JSON visit_str (0x2691150) | `research/work-items/RE-007-borrow-lend-codec-115/README.md` |
| `risk` | `0x3d44140..0x3d441f2` | 178 | 171/178 | 2 | l1/bole Operation JSON visit_str (0x3d44140) | `research/work-items/RE-007-borrow-lend-codec-115/README.md` |
| `risk` | `0x2869450..0x28694d9` | 137 | 129/137 | 2 | l1/bole BorrowLendField RMP visit_str (0x2869450) | `research/work-items/RE-007-borrow-lend-codec-115/README.md` |
| `risk` | `0x467fba0..0x467fc29` | 137 | 129/137 | 2 | l1/bole BorrowLendField RMP visit_str (0x467fba0) | `research/work-items/RE-007-borrow-lend-codec-115/README.md` |
| `risk` | `0x534bf90..0x534c019` | 137 | 129/137 | 2 | l1/bole BorrowLendField RMP visit_str (0x534bf90) | `research/work-items/RE-007-borrow-lend-codec-115/README.md` |
| `bridge` | `0x2864d00..0x2864e56` | 342 | 290/342 | 13 | l1/bridge BridgeEvent RMP visit_str (0x2864d00) | `research/work-items/bridge-event-name-codec-115/README.md` |
| `bridge` | `0x4446560..0x44466b6` | 342 | 300/342 | 13 | l1/bridge BridgeEvent RMP visit_str (0x4446560) | `research/work-items/bridge-event-name-codec-115/README.md` |
| `bridge` | `0x5ae4620..0x5ae4776` | 342 | 291/342 | 13 | l1/bridge BridgeEvent RMP visit_str (0x5ae4620) | `research/work-items/bridge-event-name-codec-115/README.md` |
| `bridge` | `0x2864e60..0x2864fd1` | 369 | 318/369 | 13 | l1/bridge BridgeEvent JSON visit_str (0x2864e60) | `research/work-items/bridge-event-name-codec-115/README.md` |
| `bridge` | `0x44466c0..0x4446831` | 369 | 328/369 | 13 | l1/bridge BridgeEvent JSON visit_str (0x44466c0) | `research/work-items/bridge-event-name-codec-115/README.md` |
| `dex-registry` | `0x2b955c0..0x2b95670` | 176 | 156/176 | 5 | l1/dex_registry DisabledState RMP visit_str (0x2b955c0) | `src/node115-hip3-disabled-state-codec/README.md` |
| `dex-registry` | `0x4446d20..0x4446dd0` | 176 | 158/176 | 5 | l1/dex_registry DisabledState RMP visit_str (0x4446d20) | `src/node115-hip3-disabled-state-codec/README.md` |
| `dex-registry` | `0x546a380..0x546a430` | 176 | 156/176 | 5 | l1/dex_registry DisabledState RMP visit_str (0x546a380) | `src/node115-hip3-disabled-state-codec/README.md` |
| `dex-registry` | `0x2b954f0..0x2b955b7` | 199 | 180/199 | 5 | l1/dex_registry DisabledState JSON visit_str (0x2b954f0) | `src/node115-hip3-disabled-state-codec/README.md` |
| `dex-registry` | `0x4446dd0..0x4446e97` | 199 | 182/199 | 5 | l1/dex_registry DisabledState JSON visit_str (0x4446dd0) | `src/node115-hip3-disabled-state-codec/README.md` |
| `evm` | `0x22dc290..0x22dc345` | 181 | 173/181 | 2 | l1/evm EvmTxType RMP visit_str (0x22dc290) | `research/work-items/evm-tx-type-name-codec-115/README.md` |
| `evm` | `0x44458a0..0x4445955` | 181 | 173/181 | 2 | l1/evm EvmTxType RMP visit_str (0x44458a0) | `research/work-items/evm-tx-type-name-codec-115/README.md` |
| `evm` | `0x5ae3fc0..0x5ae4075` | 181 | 174/181 | 2 | l1/evm EvmTxType RMP visit_str (0x5ae3fc0) | `research/work-items/evm-tx-type-name-codec-115/README.md` |
| `evm` | `0x22dde20..0x22ddeeb` | 203 | 196/203 | 2 | l1/evm EvmTxType JSON visit_str (0x22dde20) | `research/work-items/evm-tx-type-name-codec-115/README.md` |
| `evm` | `0x4445960..0x4445a2b` | 203 | 196/203 | 2 | l1/evm EvmTxType JSON visit_str (0x4445960) | `research/work-items/evm-tx-type-name-codec-115/README.md` |
| `evm` | `0x2692a20..0x2692ac1` | 161 | 150/161 | 3 | l1/evm ReadPrecompileOutcomeName RMP visit_str (0x2692a20) | `research/work-items/evm-call-outcome-codec-115/README.md` |
| `exchange` | `0x23c65f0..0x23c6716` | 294 | 266/294 | 7 | l1/exchange AbstractionKind RMP visit_str (0x23c65f0) | `research/work-items/RE-015-abstraction-kind-codec-115/README.md` |
| `exchange` | `0x3bdd720..0x3bdd846` | 294 | 266/294 | 7 | l1/exchange AbstractionKind RMP visit_str (0x3bdd720) | `research/work-items/RE-015-abstraction-kind-codec-115/README.md` |
| `exchange` | `0x4d6b5d0..0x4d6b6f6` | 294 | 266/294 | 7 | l1/exchange AbstractionKind RMP visit_str (0x4d6b5d0) | `research/work-items/RE-015-abstraction-kind-codec-115/README.md` |
| `exchange` | `0x23c6720..0x23c685f` | 319 | 292/319 | 7 | l1/exchange AbstractionKind JSON visit_str (0x23c6720) | `research/work-items/RE-015-abstraction-kind-codec-115/README.md` |
| `exchange` | `0x3bdd5e0..0x3bdd71f` | 319 | 292/319 | 7 | l1/exchange AbstractionKind JSON visit_str (0x3bdd5e0) | `research/work-items/RE-015-abstraction-kind-codec-115/README.md` |
| `consensus` | `0x23c18b0..0x23c1926` | 118 | 110/118 | 2 | l1/governance VoteChoice RMP visit_str (0x23c18b0) | `src/node115-governance-codec/README.md` |
| `consensus` | `0x3bd6f00..0x3bd6f76` | 118 | 110/118 | 2 | l1/governance VoteChoice RMP visit_str (0x3bd6f00) | `src/node115-governance-codec/README.md` |
| `consensus` | `0x4d69bd0..0x4d69c46` | 118 | 110/118 | 2 | l1/governance VoteChoice RMP visit_str (0x4d69bd0) | `src/node115-governance-codec/README.md` |
| `consensus` | `0x23c2fb0..0x23c3079` | 201 | 193/201 | 2 | l1/governance ProposalCategory RMP visit_str (0x23c2fb0) | `src/node115-governance-codec/README.md` |
| `consensus` | `0x3bd7c80..0x3bd7d49` | 201 | 193/201 | 2 | l1/governance ProposalCategory RMP visit_str (0x3bd7c80) | `src/node115-governance-codec/README.md` |
| `consensus` | `0x4d6a370..0x4d6a439` | 201 | 193/201 | 2 | l1/governance ProposalCategory RMP visit_str (0x4d6a370) | `src/node115-governance-codec/README.md` |
| `consensus` | `0x23c2ed0..0x23c2faf` | 223 | 216/223 | 2 | l1/governance ProposalCategory JSON visit_str (0x23c2ed0) | `src/node115-governance-codec/README.md` |
| `consensus` | `0x3bd7ba0..0x3bd7c7f` | 223 | 216/223 | 2 | l1/governance ProposalCategory JSON visit_str (0x3bd7ba0) | `src/node115-governance-codec/README.md` |

## Reproduce and verify

```sh
python3 research/work-items/RE-001-node115-first-party-byte-census/census.py --verify --rebuild
CARGO_BUILD_JOBS=4 RUST_TEST_THREADS=4 CARGO_TARGET_DIR=work/target/fp-census \
  cargo +1.95.0 test --offline --locked --manifest-path src/node115-first-party-byte-census/Cargo.toml
python3 -m unittest tests.test_first_party_byte_census_115 tests.test_node115_catalogue -v
```

## Limitations

- Covers bounded first-party leaf functions and serde enum visit_str visitors only; no component gate is closed.
- PC-relative and GOT relocation fields (4 bytes each) are masked by tools/byte_progress.py, not resolved to linked symbols.
- RmpErr and JsonErr model the observed error return ABI layouts without external serde/rmp_serde/serde_json crates.
- Static compilation and byte comparison only; no captured executable is run.
