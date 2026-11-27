# RE-001: Node #115 First-Party Compiled-Byte Comparison Census

- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source crate: `src/node115-first-party-byte-census/src/lib.rs` (SHA-256 `5c6ff4d3f1da176a216c39824c648b12eab6a494b383e175ad74262693bbce43`)
- Compiler: `rustc 1.95.0 (59807616e 2026-04-14)` with `--edition=2021 --crate-type=rlib --crate-name=node115_first_party_byte_census -C opt-level=3 -C overflow-checks=yes --emit=obj`
- Scope: independently authored, dependency-free, `#![forbid(unsafe_code)]` Rust implementations compiled to exact raw-equal or relocation-qualified `.text` FDE matches. Static analysis and compilation only; no captured binary is executed.

## Summary

**1008 authenticated first-party `.text` windows · 138,449 bytes compared · 127,869/138,449 (92.36%) raw-equal bytes · 6/1008 raw-equal windows · 1008/1008 (100.00%) relocation-qualified · 23 components.**

| Component | Windows | Bytes | Raw-equal bytes | Raw-equal windows | Relocation-qualified |
| --- | ---: | ---: | ---: | ---: | ---: |
| `abci` | 36 | 1,017 | 862 (84.76%) | 0/36 | 36/36 |
| `action-dispatch` | 15 | 35,135 | 33,116 (94.25%) | 0/15 | 15/15 |
| `action-wire` | 115 | 17,291 | 15,973 (92.38%) | 0/115 | 115/115 |
| `assets` | 83 | 5,385 | 4,769 (88.56%) | 3/83 | 83/83 |
| `bridge` | 45 | 4,706 | 4,234 (89.97%) | 0/45 | 45/45 |
| `consensus` | 8 | 1,403 | 1,341 (95.58%) | 0/8 | 8/8 |
| `constants` | 17 | 9,819 | 9,691 (98.70%) | 0/17 | 17/17 |
| `dex-registry` | 84 | 17,839 | 16,274 (91.23%) | 0/84 | 84/84 |
| `evm` | 61 | 2,485 | 2,217 (89.22%) | 0/61 | 61/61 |
| `evm-rpc` | 7 | 175 | 147 (84.00%) | 0/7 | 7/7 |
| `exchange` | 34 | 3,270 | 2,948 (90.15%) | 0/34 | 34/34 |
| `fees` | 70 | 3,904 | 3,446 (88.27%) | 0/70 | 70/70 |
| `foundation` | 2 | 197 | 197 (100.00%) | 2/2 | 2/2 |
| `info-api` | 42 | 3,579 | 3,245 (90.67%) | 0/42 | 42/42 |
| `l1-shared` | 10 | 311 | 275 (88.42%) | 1/10 | 10/10 |
| `node-runtime` | 11 | 527 | 471 (89.37%) | 0/11 | 11/11 |
| `orderbook` | 125 | 6,200 | 5,559 (89.66%) | 0/125 | 125/125 |
| `risk` | 84 | 6,531 | 6,029 (92.31%) | 0/84 | 84/84 |
| `serialization` | 10 | 250 | 210 (84.00%) | 0/10 | 10/10 |
| `staking` | 63 | 13,518 | 12,422 (91.89%) | 0/63 | 63/63 |
| `storage` | 14 | 886 | 800 (90.29%) | 0/14 | 14/14 |
| `transport` | 17 | 425 | 357 (84.00%) | 0/17 | 17/17 |
| `vaults` | 55 | 3,596 | 3,286 (91.38%) | 0/55 | 55/55 |

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
| `action-dispatch` | `0x2ba1af0..0x2ba2bde` | 4334 | 4007/4334 | 82 | l1/action Action (92-variant) RMP visit_str (0x2ba1af0) | `research/work-items/RE-010-action-type-matcher-115/README.md` |
| `action-dispatch` | `0x3662730..0x366381e` | 4334 | 4007/4334 | 82 | l1/action Action (92-variant) RMP visit_str (0x3662730) | `research/work-items/RE-010-action-type-matcher-115/README.md` |
| `action-dispatch` | `0x4d67530..0x4d6861e` | 4334 | 4006/4334 | 82 | l1/action Action (92-variant) RMP visit_str (0x4d67530) | `research/work-items/RE-010-action-type-matcher-115/README.md` |
| `action-dispatch` | `0x2ba0a70..0x2ba1aef` | 4223 | 3898/4223 | 82 | l1/action Action (92-variant) JSON visit_str (0x2ba0a70) | `research/work-items/RE-010-action-type-matcher-115/README.md` |
| `action-dispatch` | `0x36616b0..0x366272f` | 4223 | 3896/4223 | 82 | l1/action Action (92-variant) JSON visit_str (0x36616b0) | `research/work-items/RE-010-action-type-matcher-115/README.md` |
| `constants` | `0x14c12b0..0x14c1cac` | 2556 | 2544/2556 | 3 | global_constants NodeEnv (79-variant) RMP visit_str (0x14c12b0) | `research/work-items/RE-010-env79-variant-matchers-115/README.md` |
| `constants` | `0x14c07c0..0x14c12a1` | 2785 | 2774/2785 | 3 | global_constants NodeEnv (79-variant) JSON visit_str (0x14c07c0) | `research/work-items/RE-010-env79-variant-matchers-115/README.md` |
| `constants` | `0x1774100..0x1774be1` | 2785 | 2775/2785 | 3 | global_constants NodeEnv (79-variant) JSON visit_str (0x1774100) | `research/work-items/RE-010-env79-variant-matchers-115/README.md` |
| `action-dispatch` | `0x287ec80..0x287f361` | 1761 | 1749/1761 | 3 | l1/action ShortActionTag (114-variant) RMP visit_str (0x287ec80) | `research/work-items/RE-010-enum-variant-matchers-115/README.md` |
| `action-dispatch` | `0x468fbd0..0x46902b1` | 1761 | 1749/1761 | 3 | l1/action ShortActionTag (114-variant) RMP visit_str (0x468fbd0) | `research/work-items/RE-010-enum-variant-matchers-115/README.md` |
| `action-dispatch` | `0x5357ff0..0x53586d1` | 1761 | 1749/1761 | 3 | l1/action ShortActionTag (114-variant) RMP visit_str (0x5357ff0) | `research/work-items/RE-010-enum-variant-matchers-115/README.md` |
| `action-dispatch` | `0x287e450..0x287ec7f` | 2095 | 2084/2095 | 3 | l1/action ShortActionTag (114-variant) JSON visit_str (0x287e450) | `research/work-items/RE-010-enum-variant-matchers-115/README.md` |
| `action-dispatch` | `0x468f3a0..0x468fbcf` | 2095 | 2083/2095 | 3 | l1/action ShortActionTag (114-variant) JSON visit_str (0x468f3a0) | `research/work-items/RE-010-enum-variant-matchers-115/README.md` |
| `action-dispatch` | `0x2ba5c90..0x2ba5fd4` | 836 | 764/836 | 18 | l1/exchange PerpDeploy (16-variant + alias) RMP visit_str (0x2ba5c90) | `research/work-items/RE-010-enum-variant-matchers-115/README.md` |
| `action-dispatch` | `0x444f660..0x444f9a4` | 836 | 780/836 | 18 | l1/exchange PerpDeploy (16-variant + alias) RMP visit_str (0x444f660) | `research/work-items/RE-010-enum-variant-matchers-115/README.md` |
| `action-dispatch` | `0x5471cb0..0x5471ff4` | 836 | 765/836 | 18 | l1/exchange PerpDeploy (16-variant + alias) RMP visit_str (0x5471cb0) | `research/work-items/RE-010-enum-variant-matchers-115/README.md` |
| `action-dispatch` | `0x2ba5930..0x2ba5c85` | 853 | 782/853 | 18 | l1/exchange PerpDeploy (16-variant + alias) JSON visit_str (0x2ba5930) | `research/work-items/RE-010-enum-variant-matchers-115/README.md` |
| `action-dispatch` | `0x444f9b0..0x444fd05` | 853 | 797/853 | 18 | l1/exchange PerpDeploy (16-variant + alias) JSON visit_str (0x444f9b0) | `research/work-items/RE-010-enum-variant-matchers-115/README.md` |
| `dex-registry` | `0x2ba41c0..0x2ba432e` | 366 | 346/366 | 5 | l1/dex_registry Hip3Star (8-variant) RMP visit_str (0x2ba41c0) | `research/work-items/dex-registry-sub-deployers-115/README.md` |
| `dex-registry` | `0x444db70..0x444dcde` | 366 | 348/366 | 5 | l1/dex_registry Hip3Star (8-variant) RMP visit_str (0x444db70) | `research/work-items/dex-registry-sub-deployers-115/README.md` |
| `dex-registry` | `0x5470720..0x547088e` | 366 | 346/366 | 5 | l1/dex_registry Hip3Star (8-variant) RMP visit_str (0x5470720) | `research/work-items/dex-registry-sub-deployers-115/README.md` |
| `dex-registry` | `0x2ba4030..0x2ba41b5` | 389 | 370/389 | 5 | l1/dex_registry Hip3Star (8-variant) JSON visit_str (0x2ba4030) | `research/work-items/dex-registry-sub-deployers-115/README.md` |
| `dex-registry` | `0x444dce0..0x444de65` | 389 | 372/389 | 5 | l1/dex_registry Hip3Star (8-variant) JSON visit_str (0x444dce0) | `research/work-items/dex-registry-sub-deployers-115/README.md` |
| `dex-registry` | `0x2b94d80..0x2b94dc3` | 67 | 59/67 | 2 | l1/dex_registry Main/Hip3 RMP visit_str (0x2b94d80) | `research/work-items/dex-registry-main-hip3-state-codec-115/README.md` |
| `dex-registry` | `0x4440220..0x4440263` | 67 | 59/67 | 2 | l1/dex_registry Main/Hip3 RMP visit_str (0x4440220) | `research/work-items/dex-registry-main-hip3-state-codec-115/README.md` |
| `dex-registry` | `0x5469f10..0x5469f53` | 67 | 59/67 | 2 | l1/dex_registry Main/Hip3 RMP visit_str (0x5469f10) | `research/work-items/dex-registry-main-hip3-state-codec-115/README.md` |
| `dex-registry` | `0x287b080..0x287b3ea` | 874 | 802/874 | 18 | l1/dex_registry PerpDeployActionV2 (18-variant) RMP visit_str (0x287b080) | `research/work-items/RE-010-enum-variant-matchers-115/README.md` |
| `dex-registry` | `0x3666e10..0x366717a` | 874 | 803/874 | 18 | l1/dex_registry PerpDeployActionV2 (18-variant) RMP visit_str (0x3666e10) | `research/work-items/RE-010-enum-variant-matchers-115/README.md` |
| `dex-registry` | `0x5174d70..0x51750da` | 874 | 803/874 | 18 | l1/dex_registry PerpDeployActionV2 (18-variant) RMP visit_str (0x5174d70) | `research/work-items/RE-010-enum-variant-matchers-115/README.md` |
| `dex-registry` | `0x287acf0..0x287b078` | 904 | 834/904 | 18 | l1/dex_registry PerpDeployActionV2 (18-variant) JSON visit_str (0x287acf0) | `research/work-items/RE-010-enum-variant-matchers-115/README.md` |
| `dex-registry` | `0x3667180..0x3667508` | 904 | 833/904 | 18 | l1/dex_registry PerpDeployActionV2 (18-variant) JSON visit_str (0x3667180) | `research/work-items/RE-010-enum-variant-matchers-115/README.md` |
| `dex-registry` | `0x2888560..0x2888837` | 727 | 640/727 | 22 | l1/dex_registry OutcomeDeployAction (13-variant) RMP visit_str (0x2888560) | `research/work-items/RE-007-node115-outcome-tracker/README.md` |
| `dex-registry` | `0x445bbc0..0x445be97` | 727 | 639/727 | 22 | l1/dex_registry OutcomeDeployAction (13-variant) RMP visit_str (0x445bbc0) | `research/work-items/RE-007-node115-outcome-tracker/README.md` |
| `dex-registry` | `0x50b8e50..0x50b9127` | 727 | 639/727 | 22 | l1/dex_registry OutcomeDeployAction (13-variant) RMP visit_str (0x50b8e50) | `research/work-items/RE-007-node115-outcome-tracker/README.md` |
| `dex-registry` | `0x2888290..0x2888553` | 707 | 620/707 | 22 | l1/dex_registry OutcomeDeployAction (13-variant) JSON visit_str (0x2888290) | `research/work-items/RE-007-node115-outcome-tracker/README.md` |
| `dex-registry` | `0x445bea0..0x445c163` | 707 | 620/707 | 22 | l1/dex_registry OutcomeDeployAction (13-variant) JSON visit_str (0x445bea0) | `research/work-items/RE-007-node115-outcome-tracker/README.md` |
| `info-api` | `0x2744200..0x2744bfa` | 2554 | 2383/2554 | 43 | info_server InfoRequest (55-variant) JSON visit_str (0x2744200) | `research/work-items/RE-015-node115-info-api-crate/README.md` |
| `assets` | `0x287ca20..0x287cd56` | 822 | 750/822 | 18 | l1/spot_meta SpotDeployAction (16-variant) RMP visit_str (0x287ca20) | `research/work-items/RE-004-node115-assets-meta-deployer-qtys/README.md` |
| `assets` | `0x53570d0..0x5357406` | 822 | 750/822 | 18 | l1/spot_meta SpotDeployAction (16-variant) RMP visit_str (0x53570d0) | `research/work-items/RE-004-node115-assets-meta-deployer-qtys/README.md` |
| `assets` | `0x287cd60..0x287d0b5` | 853 | 782/853 | 18 | l1/spot_meta SpotDeployAction (16-variant) JSON visit_str (0x287cd60) | `research/work-items/RE-004-node115-assets-meta-deployer-qtys/README.md` |
| `action-wire` | `0x28838d0..0x2883a17` | 327 | 307/327 | 5 | l1/action AgentAction (7-variant) RMP visit_str (0x28838d0) | `research/work-items/RE-010-action-type-matcher-115/README.md` |
| `action-wire` | `0x3668c00..0x3668d47` | 327 | 307/327 | 5 | l1/action AgentAction (7-variant) RMP visit_str (0x3668c00) | `research/work-items/RE-010-action-type-matcher-115/README.md` |
| `action-wire` | `0x5175f10..0x5176057` | 327 | 307/327 | 5 | l1/action AgentAction (7-variant) RMP visit_str (0x5175f10) | `research/work-items/RE-010-action-type-matcher-115/README.md` |
| `action-wire` | `0x2883770..0x28838ce` | 350 | 331/350 | 5 | l1/action AgentAction (7-variant) JSON visit_str (0x2883770) | `research/work-items/RE-010-action-type-matcher-115/README.md` |
| `action-wire` | `0x3668aa0..0x3668bfe` | 350 | 331/350 | 5 | l1/action AgentAction (7-variant) JSON visit_str (0x3668aa0) | `research/work-items/RE-010-action-type-matcher-115/README.md` |
| `dex-registry` | `0x2749530..0x2749646` | 278 | 242/278 | 9 | l1/dex_registry OutcomeTemplateAction (5-variant) RMP visit_str (0x2749530) | `research/work-items/RE-007-node115-outcome-tracker/README.md` |
| `dex-registry` | `0x3be0a10..0x3be0b26` | 278 | 242/278 | 9 | l1/dex_registry OutcomeTemplateAction (5-variant) RMP visit_str (0x3be0a10) | `research/work-items/RE-007-node115-outcome-tracker/README.md` |
| `dex-registry` | `0x4d6c710..0x4d6c826` | 278 | 242/278 | 9 | l1/dex_registry OutcomeTemplateAction (5-variant) RMP visit_str (0x4d6c710) | `research/work-items/RE-007-node115-outcome-tracker/README.md` |
| `dex-registry` | `0x2749410..0x2749527` | 279 | 244/279 | 9 | l1/dex_registry OutcomeTemplateAction (5-variant) JSON visit_str (0x2749410) | `research/work-items/RE-007-node115-outcome-tracker/README.md` |
| `dex-registry` | `0x3be08f0..0x3be0a07` | 279 | 244/279 | 9 | l1/dex_registry OutcomeTemplateAction (5-variant) JSON visit_str (0x3be08f0) | `research/work-items/RE-007-node115-outcome-tracker/README.md` |
| `dex-registry` | `0x25d3240..0x25d333c` | 252 | 240/252 | 3 | l1/dex_registry OutcomeFieldType (7-variant) RMP visit_str (0x25d3240) | `research/work-items/RE-007-node115-outcome-tracker/README.md` |
| `dex-registry` | `0x44623c0..0x44624bc` | 252 | 240/252 | 3 | l1/dex_registry OutcomeFieldType (7-variant) RMP visit_str (0x44623c0) | `research/work-items/RE-007-node115-outcome-tracker/README.md` |
| `dex-registry` | `0x5478dd0..0x5478ecc` | 252 | 240/252 | 3 | l1/dex_registry OutcomeFieldType (7-variant) RMP visit_str (0x5478dd0) | `research/work-items/RE-007-node115-outcome-tracker/README.md` |
| `dex-registry` | `0x25d3340..0x25d3456` | 278 | 267/278 | 3 | l1/dex_registry OutcomeFieldType (7-variant) JSON visit_str (0x25d3340) | `research/work-items/RE-007-node115-outcome-tracker/README.md` |
| `dex-registry` | `0x44622a0..0x44623b6` | 278 | 267/278 | 3 | l1/dex_registry OutcomeFieldType (7-variant) JSON visit_str (0x44622a0) | `research/work-items/RE-007-node115-outcome-tracker/README.md` |
| `orderbook` | `0x23bc920..0x23bc9be` | 158 | 146/158 | 3 | l1/book OrderGrouping (4-variant) RMP visit_str (0x23bc920) | `research/work-items/RE-006-node115-twap-trigger-cloid/README.md` |
| `orderbook` | `0x41fdc70..0x41fdd0e` | 158 | 146/158 | 3 | l1/book OrderGrouping (4-variant) RMP visit_str (0x41fdc70) | `research/work-items/RE-006-node115-twap-trigger-cloid/README.md` |
| `orderbook` | `0x50b6300..0x50b639e` | 158 | 146/158 | 3 | l1/book OrderGrouping (4-variant) RMP visit_str (0x50b6300) | `research/work-items/RE-006-node115-twap-trigger-cloid/README.md` |
| `orderbook` | `0x23bc860..0x23bc914` | 180 | 169/180 | 3 | l1/book OrderGrouping (4-variant) JSON visit_str (0x23bc860) | `research/work-items/RE-006-node115-twap-trigger-cloid/README.md` |
| `orderbook` | `0x41fdd10..0x41fddc4` | 180 | 169/180 | 3 | l1/book OrderGrouping (4-variant) JSON visit_str (0x41fdd10) | `research/work-items/RE-006-node115-twap-trigger-cloid/README.md` |
| `dex-registry` | `0x2889880..0x2889922` | 162 | 146/162 | 4 | l1/dex_registry OutcomeEntryKind (3-variant) RMP visit_str (0x2889880) | `research/work-items/RE-007-node115-outcome-tracker/README.md` |
| `dex-registry` | `0x445c860..0x445c902` | 162 | 146/162 | 4 | l1/dex_registry OutcomeEntryKind (3-variant) RMP visit_str (0x445c860) | `research/work-items/RE-007-node115-outcome-tracker/README.md` |
| `dex-registry` | `0x50b9af0..0x50b9b92` | 162 | 146/162 | 4 | l1/dex_registry OutcomeEntryKind (3-variant) RMP visit_str (0x50b9af0) | `research/work-items/RE-007-node115-outcome-tracker/README.md` |
| `staking` | `0x25d1ea0..0x25d1f39` | 153 | 145/153 | 2 | l1/c_staking StakingLink (3-variant) RMP visit_str (0x25d1ea0) | `research/work-items/RE-008-node115-staking-crate-map/README.md` |
| `staking` | `0x468cd50..0x468cde9` | 153 | 145/153 | 2 | l1/c_staking StakingLink (3-variant) RMP visit_str (0x468cd50) | `research/work-items/RE-008-node115-staking-crate-map/README.md` |
| `staking` | `0x5355580..0x5355619` | 153 | 145/153 | 2 | l1/c_staking StakingLink (3-variant) RMP visit_str (0x5355580) | `research/work-items/RE-008-node115-staking-crate-map/README.md` |
| `staking` | `0x2879540..0x28795d4` | 148 | 140/148 | 2 | l1/c_staking CValidatorAction (3-variant) RMP visit_str (0x2879540) | `research/work-items/RE-008-node115-staking-crate-map/README.md` |
| `staking` | `0x4454fb0..0x4455044` | 148 | 140/148 | 2 | l1/c_staking CValidatorAction (3-variant) RMP visit_str (0x4454fb0) | `research/work-items/RE-008-node115-staking-crate-map/README.md` |
| `staking` | `0x5356510..0x53565a4` | 148 | 140/148 | 2 | l1/c_staking CValidatorAction (3-variant) RMP visit_str (0x5356510) | `research/work-items/RE-008-node115-staking-crate-map/README.md` |
| `dex-registry` | `0x28819f0..0x2881abb` | 203 | 195/203 | 2 | l1/dex_registry OutcomeTokenOp (4-variant) RMP visit_str (0x28819f0) | `research/work-items/RE-007-node115-outcome-tracker/README.md` |
| `dex-registry` | `0x2881900..0x28819e1` | 225 | 218/225 | 2 | l1/dex_registry OutcomeTokenOp (4-variant) JSON visit_str (0x2881900) | `research/work-items/RE-007-node115-outcome-tracker/README.md` |
| `risk` | `0x2ba3680..0x2ba3707` | 135 | 127/135 | 2 | l1/clearinghouse AssetTradingMode (3-variant) RMP visit_str (0x2ba3680) | `research/work-items/RE-007-node115-clearinghouse-margin-user-state/README.md` |
| `risk` | `0x444d1c0..0x444d247` | 135 | 127/135 | 2 | l1/clearinghouse AssetTradingMode (3-variant) RMP visit_str (0x444d1c0) | `research/work-items/RE-007-node115-clearinghouse-margin-user-state/README.md` |
| `risk` | `0x5470200..0x5470287` | 135 | 127/135 | 2 | l1/clearinghouse AssetTradingMode (3-variant) RMP visit_str (0x5470200) | `research/work-items/RE-007-node115-clearinghouse-margin-user-state/README.md` |
| `vaults` | `0x28675e0..0x286765e` | 126 | 118/126 | 2 | l1/vault VaultRelationship (3-variant) RMP visit_str (0x28675e0) | `research/work-items/RE-007-node115-vault-distribute-and-map/README.md` |
| `vaults` | `0x4447b20..0x4447b9e` | 126 | 118/126 | 2 | l1/vault VaultRelationship (3-variant) RMP visit_str (0x4447b20) | `research/work-items/RE-007-node115-vault-distribute-and-map/README.md` |
| `vaults` | `0x4d63590..0x4d6360e` | 126 | 118/126 | 2 | l1/vault VaultRelationship (3-variant) RMP visit_str (0x4d63590) | `research/work-items/RE-007-node115-vault-distribute-and-map/README.md` |
| `exchange` | `0x28685e0..0x2868657` | 119 | 111/119 | 2 | l1/exchange AccountMode (3-variant) RMP visit_str (0x28685e0) | `research/work-items/RE-010-action-type-matcher-115/README.md` |
| `exchange` | `0x3bcf630..0x3bcf6a7` | 119 | 111/119 | 2 | l1/exchange AccountMode (3-variant) RMP visit_str (0x3bcf630) | `research/work-items/RE-010-action-type-matcher-115/README.md` |
| `exchange` | `0x59fdca0..0x59fdd17` | 119 | 112/119 | 2 | l1/exchange AccountMode (3-variant) RMP visit_str (0x59fdca0) | `research/work-items/RE-010-action-type-matcher-115/README.md` |
| `risk` | `0x29a0140..0x29a01ae` | 110 | 102/110 | 2 | l1/clearinghouse OracleSourceKind (2-variant) RMP visit_str (0x29a0140) | `research/work-items/RE-007-node115-clearinghouse-oracle-and-source-map/README.md` |
| `risk` | `0x366a4b0..0x366a51e` | 110 | 102/110 | 2 | l1/clearinghouse OracleSourceKind (2-variant) RMP visit_str (0x366a4b0) | `research/work-items/RE-007-node115-clearinghouse-oracle-and-source-map/README.md` |
| `risk` | `0x51772c0..0x517732e` | 110 | 102/110 | 2 | l1/clearinghouse OracleSourceKind (2-variant) RMP visit_str (0x51772c0) | `research/work-items/RE-007-node115-clearinghouse-oracle-and-source-map/README.md` |
| `node-runtime` | `0x22e0520..0x22e058d` | 109 | 101/109 | 2 | node NodeStreamRole (Evm/Broadcaster) RMP visit_str (0x22e0520) | `research/work-items/RE-012-node115-artifact-and-stream-msg/README.md` |
| `node-runtime` | `0x3bd37f0..0x3bd385d` | 109 | 101/109 | 2 | node NodeStreamRole (Evm/Broadcaster) RMP visit_str (0x3bd37f0) | `research/work-items/RE-012-node115-artifact-and-stream-msg/README.md` |
| `node-runtime` | `0x54725a0..0x547260d` | 109 | 101/109 | 2 | node NodeStreamRole (Evm/Broadcaster) RMP visit_str (0x54725a0) | `research/work-items/RE-012-node115-artifact-and-stream-msg/README.md` |
| `risk` | `0x274a290..0x274a2f5` | 101 | 93/101 | 2 | l1/clearinghouse SpotPxKind (2-variant) RMP visit_str (0x274a290) | `research/work-items/RE-007-node115-clearinghouse-oracle-and-source-map/README.md` |
| `risk` | `0x4200040..0x42000a5` | 101 | 93/101 | 2 | l1/clearinghouse SpotPxKind (2-variant) RMP visit_str (0x4200040) | `research/work-items/RE-007-node115-clearinghouse-oracle-and-source-map/README.md` |
| `risk` | `0x4d6d100..0x4d6d165` | 101 | 93/101 | 2 | l1/clearinghouse SpotPxKind (2-variant) RMP visit_str (0x4d6d100) | `research/work-items/RE-007-node115-clearinghouse-oracle-and-source-map/README.md` |
| `staking` | `0x299ec70..0x299ecd2` | 98 | 90/98 | 2 | l1/c_staking StakerRoleKind (2-variant) RMP visit_str (0x299ec70) | `research/work-items/RE-008-node115-staking-crate-map/README.md` |
| `staking` | `0x46938c0..0x4693922` | 98 | 90/98 | 2 | l1/c_staking StakerRoleKind (2-variant) RMP visit_str (0x46938c0) | `research/work-items/RE-008-node115-staking-crate-map/README.md` |
| `staking` | `0x50b8010..0x50b8072` | 98 | 90/98 | 2 | l1/c_staking StakerRoleKind (2-variant) RMP visit_str (0x50b8010) | `research/work-items/RE-008-node115-staking-crate-map/README.md` |
| `orderbook` | `0x23bcb50..0x23bcb91` | 65 | 57/65 | 2 | l1/book TpslKind (tp/sl) RMP visit_str (0x23bcb50) | `research/work-items/RE-006-node115-twap-trigger-cloid/README.md` |
| `orderbook` | `0x444abf0..0x444ac31` | 65 | 57/65 | 2 | l1/book TpslKind (tp/sl) RMP visit_str (0x444abf0) | `research/work-items/RE-006-node115-twap-trigger-cloid/README.md` |
| `orderbook` | `0x59fe180..0x59fe1c1` | 65 | 58/65 | 2 | l1/book TpslKind (tp/sl) RMP visit_str (0x59fe180) | `research/work-items/RE-006-node115-twap-trigger-cloid/README.md` |
| `abci` | `0x2885db0..0x2885df0` | 64 | 56/64 | 2 | l1/abci QuorumStatus (Q/N) RMP visit_str (0x2885db0) | `research/work-items/RE-009-node115-storage-abci-byte-matches/README.md` |
| `abci` | `0x3668e30..0x3668e70` | 64 | 56/64 | 2 | l1/abci QuorumStatus (Q/N) RMP visit_str (0x3668e30) | `research/work-items/RE-009-node115-storage-abci-byte-matches/README.md` |
| `abci` | `0x535a8f0..0x535a930` | 64 | 56/64 | 2 | l1/abci QuorumStatus (Q/N) RMP visit_str (0x535a8f0) | `research/work-items/RE-009-node115-storage-abci-byte-matches/README.md` |
| `storage` | `0x1500470..0x1500595` | 293 | 274/293 | 5 | db IndexedArtifactContentSerde (5-variant) JSON visit_str (0x1500470) | `research/work-items/RE-009-node115-storage-abci-byte-matches/README.md` |
| `storage` | `0x57c41a0..0x57c42c5` | 293 | 274/293 | 5 | db IndexedArtifactContentSerde (5-variant) JSON visit_str (0x57c41a0) | `research/work-items/RE-009-node115-storage-abci-byte-matches/README.md` |
| `action-wire` | `0x23c9a00..0x23c9bc3` | 451 | 415/451 | 9 | l1/action SendAssetCrossChainAction fields (11f) RMP visit_str (0x23c9a00) | `research/work-items/RE-010-action-type-matcher-115/README.md` |
| `action-wire` | `0x4463e30..0x4463ff3` | 451 | 415/451 | 9 | l1/action SendAssetCrossChainAction fields (11f) RMP visit_str (0x4463e30) | `research/work-items/RE-010-action-type-matcher-115/README.md` |
| `action-wire` | `0x58db7e0..0x58db9a3` | 451 | 416/451 | 9 | l1/action SendAssetCrossChainAction fields (11f) RMP visit_str (0x58db7e0) | `research/work-items/RE-010-action-type-matcher-115/README.md` |
| `action-wire` | `0x23c9bd0..0x23c9dad` | 477 | 442/477 | 9 | l1/action SendAssetCrossChainAction fields (11f) JSON visit_str (0x23c9bd0) | `research/work-items/RE-010-action-type-matcher-115/README.md` |
| `action-wire` | `0x4464000..0x44641dd` | 477 | 442/477 | 9 | l1/action SendAssetCrossChainAction fields (11f) JSON visit_str (0x4464000) | `research/work-items/RE-010-action-type-matcher-115/README.md` |
| `action-wire` | `0x23c1370..0x23c14ef` | 383 | 363/383 | 5 | l1/action SendAssetSignedAction fields (9f) RMP visit_str (0x23c1370) | `research/work-items/RE-010-action-type-matcher-115/README.md` |
| `action-wire` | `0x4454a20..0x4454b9f` | 383 | 365/383 | 5 | l1/action SendAssetSignedAction fields (9f) RMP visit_str (0x4454a20) | `research/work-items/RE-010-action-type-matcher-115/README.md` |
| `action-wire` | `0x58d8680..0x58d87ff` | 383 | 364/383 | 5 | l1/action SendAssetSignedAction fields (9f) RMP visit_str (0x58d8680) | `research/work-items/RE-010-action-type-matcher-115/README.md` |
| `action-wire` | `0x23c14f0..0x23c1687` | 407 | 388/407 | 5 | l1/action SendAssetSignedAction fields (9f) JSON visit_str (0x23c14f0) | `research/work-items/RE-010-action-type-matcher-115/README.md` |
| `action-wire` | `0x4454880..0x4454a17` | 407 | 390/407 | 5 | l1/action SendAssetSignedAction fields (9f) JSON visit_str (0x4454880) | `research/work-items/RE-010-action-type-matcher-115/README.md` |
| `action-wire` | `0x23c5bf0..0x23c5d27` | 311 | 299/311 | 3 | l1/action SendAssetAction fields (7f) RMP visit_str (0x23c5bf0) | `research/work-items/RE-010-action-type-matcher-115/README.md` |
| `action-wire` | `0x4694d00..0x4694e37` | 311 | 299/311 | 3 | l1/action SendAssetAction fields (7f) RMP visit_str (0x4694d00) | `research/work-items/RE-010-action-type-matcher-115/README.md` |
| `action-wire` | `0x58d9480..0x58d95b7` | 311 | 300/311 | 3 | l1/action SendAssetAction fields (7f) RMP visit_str (0x58d9480) | `research/work-items/RE-010-action-type-matcher-115/README.md` |
| `action-wire` | `0x23c5d30..0x23c5e7d` | 333 | 322/333 | 3 | l1/action SendAssetAction fields (7f) JSON visit_str (0x23c5d30) | `research/work-items/RE-010-action-type-matcher-115/README.md` |
| `action-wire` | `0x4694e40..0x4694f8d` | 333 | 321/333 | 3 | l1/action SendAssetAction fields (7f) JSON visit_str (0x4694e40) | `research/work-items/RE-010-action-type-matcher-115/README.md` |
| `staking` | `0x2890740..0x289086b` | 299 | 279/299 | 5 | l1/c_staking CValidatorChangeProfile fields (7f) RMP visit_str (0x2890740) | `research/work-items/RE-008-node115-staking-crate-map/README.md` |
| `staking` | `0x4467c30..0x4467d5b` | 299 | 279/299 | 5 | l1/c_staking CValidatorChangeProfile fields (7f) RMP visit_str (0x4467c30) | `research/work-items/RE-008-node115-staking-crate-map/README.md` |
| `staking` | `0x535e200..0x535e32b` | 299 | 279/299 | 5 | l1/c_staking CValidatorChangeProfile fields (7f) RMP visit_str (0x535e200) | `research/work-items/RE-008-node115-staking-crate-map/README.md` |
| `staking` | `0x28905f0..0x2890732` | 322 | 303/322 | 5 | l1/c_staking CValidatorChangeProfile fields (7f) JSON visit_str (0x28905f0) | `research/work-items/RE-008-node115-staking-crate-map/README.md` |
| `staking` | `0x4467ae0..0x4467c22` | 322 | 303/322 | 5 | l1/c_staking CValidatorChangeProfile fields (7f) JSON visit_str (0x4467ae0) | `research/work-items/RE-008-node115-staking-crate-map/README.md` |
| `action-wire` | `0x288b1d0..0x288b2f9` | 297 | 277/297 | 5 | l1/action SendAssetInternalAction fields (6f) RMP visit_str (0x288b1d0) | `research/work-items/RE-010-action-type-matcher-115/README.md` |
| `action-wire` | `0x445f280..0x445f3a9` | 297 | 277/297 | 5 | l1/action SendAssetInternalAction fields (6f) RMP visit_str (0x445f280) | `research/work-items/RE-010-action-type-matcher-115/README.md` |
| `action-wire` | `0x58da1f0..0x58da319` | 297 | 278/297 | 5 | l1/action SendAssetInternalAction fields (6f) RMP visit_str (0x58da1f0) | `research/work-items/RE-010-action-type-matcher-115/README.md` |
| `action-wire` | `0x288b300..0x288b441` | 321 | 303/321 | 5 | l1/action SendAssetInternalAction fields (6f) JSON visit_str (0x288b300) | `research/work-items/RE-010-action-type-matcher-115/README.md` |
| `action-wire` | `0x445f3b0..0x445f4f1` | 321 | 302/321 | 5 | l1/action SendAssetInternalAction fields (6f) JSON visit_str (0x445f3b0) | `research/work-items/RE-010-action-type-matcher-115/README.md` |
| `staking` | `0x28916b0..0x28917ca` | 282 | 254/282 | 7 | l1/c_staking TreasuryStakerConfig fields (5f) RMP visit_str (0x28916b0) | `research/work-items/RE-008-node115-staking-crate-map/README.md` |
| `staking` | `0x4699fc0..0x469a0da` | 282 | 254/282 | 7 | l1/c_staking TreasuryStakerConfig fields (5f) RMP visit_str (0x4699fc0) | `research/work-items/RE-008-node115-staking-crate-map/README.md` |
| `staking` | `0x50ba750..0x50ba86a` | 282 | 254/282 | 7 | l1/c_staking TreasuryStakerConfig fields (5f) RMP visit_str (0x50ba750) | `research/work-items/RE-008-node115-staking-crate-map/README.md` |
| `staking` | `0x28917d0..0x2891902` | 306 | 279/306 | 7 | l1/c_staking TreasuryStakerConfig fields (5f) JSON visit_str (0x28917d0) | `research/work-items/RE-008-node115-staking-crate-map/README.md` |
| `staking` | `0x4699e80..0x4699fb2` | 306 | 278/306 | 7 | l1/c_staking TreasuryStakerConfig fields (5f) JSON visit_str (0x4699e80) | `research/work-items/RE-008-node115-staking-crate-map/README.md` |
| `staking` | `0x23c3f80..0x23c4081` | 257 | 237/257 | 5 | l1/c_staking TokenDelegateAction fields (6f) RMP visit_str (0x23c3f80) | `research/work-items/RE-008-node115-staking-delegation/README.md` |
| `staking` | `0x4459a90..0x4459b91` | 257 | 237/257 | 5 | l1/c_staking TokenDelegateAction fields (6f) RMP visit_str (0x4459a90) | `research/work-items/RE-008-node115-staking-delegation/README.md` |
| `staking` | `0x535a350..0x535a451` | 257 | 237/257 | 5 | l1/c_staking TokenDelegateAction fields (6f) RMP visit_str (0x535a350) | `research/work-items/RE-008-node115-staking-delegation/README.md` |
| `staking` | `0x23c3e60..0x23c3f7a` | 282 | 263/282 | 5 | l1/c_staking TokenDelegateAction fields (6f) JSON visit_str (0x23c3e60) | `research/work-items/RE-008-node115-staking-delegation/README.md` |
| `staking` | `0x4459ba0..0x4459cba` | 282 | 263/282 | 5 | l1/c_staking TokenDelegateAction fields (6f) JSON visit_str (0x4459ba0) | `research/work-items/RE-008-node115-staking-delegation/README.md` |
| `orderbook` | `0x288c990..0x288ca8b` | 251 | 239/251 | 3 | l1/book TrailingStopOrder fields (6f) RMP visit_str (0x288c990) | `research/work-items/RE-006-node115-twap-trigger-cloid/README.md` |
| `orderbook` | `0x46968d0..0x46969cb` | 251 | 239/251 | 3 | l1/book TrailingStopOrder fields (6f) RMP visit_str (0x46968d0) | `research/work-items/RE-006-node115-twap-trigger-cloid/README.md` |
| `orderbook` | `0x5176ba0..0x5176c9b` | 251 | 240/251 | 3 | l1/book TrailingStopOrder fields (6f) RMP visit_str (0x5176ba0) | `research/work-items/RE-006-node115-twap-trigger-cloid/README.md` |
| `orderbook` | `0x288c870..0x288c981` | 273 | 262/273 | 3 | l1/book TrailingStopOrder fields (6f) JSON visit_str (0x288c870) | `research/work-items/RE-006-node115-twap-trigger-cloid/README.md` |
| `orderbook` | `0x46967b0..0x46968c1` | 273 | 261/273 | 3 | l1/book TrailingStopOrder fields (6f) JSON visit_str (0x46967b0) | `research/work-items/RE-006-node115-twap-trigger-cloid/README.md` |
| `staking` | `0x23c26e0..0x23c27d8` | 248 | 228/248 | 5 | l1/governance GovProposeAction fields (6f) RMP visit_str (0x23c26e0) | `research/work-items/RE-008-node115-staking-delegation/README.md` |
| `staking` | `0x4455790..0x4455888` | 248 | 229/248 | 5 | l1/governance GovProposeAction fields (6f) RMP visit_str (0x4455790) | `research/work-items/RE-008-node115-staking-delegation/README.md` |
| `staking` | `0x58d8b20..0x58d8c18` | 248 | 229/248 | 5 | l1/governance GovProposeAction fields (6f) RMP visit_str (0x58d8b20) | `research/work-items/RE-008-node115-staking-delegation/README.md` |
| `staking` | `0x23c25d0..0x23c26e0` | 272 | 253/272 | 5 | l1/governance GovProposeAction fields (6f) JSON visit_str (0x23c25d0) | `research/work-items/RE-008-node115-staking-delegation/README.md` |
| `staking` | `0x4455680..0x4455790` | 272 | 254/272 | 5 | l1/governance GovProposeAction fields (6f) JSON visit_str (0x4455680) | `research/work-items/RE-008-node115-staking-delegation/README.md` |
| `action-wire` | `0x23c0170..0x23c0264` | 244 | 224/244 | 5 | l1/action SpotSendAction fields (6f) RMP visit_str (0x23c0170) | `research/work-items/RE-010-action-type-matcher-115/README.md` |
| `action-wire` | `0x4453530..0x4453624` | 244 | 226/244 | 5 | l1/action SpotSendAction fields (6f) RMP visit_str (0x4453530) | `research/work-items/RE-010-action-type-matcher-115/README.md` |
| `action-wire` | `0x58d7dc0..0x58d7eb4` | 244 | 225/244 | 5 | l1/action SpotSendAction fields (6f) RMP visit_str (0x58d7dc0) | `research/work-items/RE-010-action-type-matcher-115/README.md` |
| `action-wire` | `0x23c0270..0x23c037c` | 268 | 249/268 | 5 | l1/action SpotSendAction fields (6f) JSON visit_str (0x23c0270) | `research/work-items/RE-010-action-type-matcher-115/README.md` |
| `action-wire` | `0x4453630..0x445373c` | 268 | 251/268 | 5 | l1/action SpotSendAction fields (6f) JSON visit_str (0x4453630) | `research/work-items/RE-010-action-type-matcher-115/README.md` |
| `staking` | `0x2d153c0..0x2d154aa` | 234 | 214/234 | 5 | l1/c_staking ValidatorColdUserLink fields (5f) RMP visit_str (0x2d153c0) | `research/work-items/RE-008-node115-staking-crate-map/README.md` |
| `staking` | `0x4461240..0x446132a` | 234 | 214/234 | 5 | l1/c_staking ValidatorColdUserLink fields (5f) RMP visit_str (0x4461240) | `research/work-items/RE-008-node115-staking-crate-map/README.md` |
| `staking` | `0x58daa20..0x58dab0a` | 234 | 215/234 | 5 | l1/c_staking ValidatorColdUserLink fields (5f) RMP visit_str (0x58daa20) | `research/work-items/RE-008-node115-staking-crate-map/README.md` |
| `staking` | `0x2d152b0..0x2d153b1` | 257 | 237/257 | 5 | l1/c_staking ValidatorColdUserLink fields (5f) JSON visit_str (0x2d152b0) | `research/work-items/RE-008-node115-staking-crate-map/README.md` |
| `staking` | `0x4461130..0x4461231` | 257 | 238/257 | 5 | l1/c_staking ValidatorColdUserLink fields (5f) JSON visit_str (0x4461130) | `research/work-items/RE-008-node115-staking-crate-map/README.md` |
| `fees` | `0x23c4af0..0x23c4bd2` | 226 | 202/226 | 6 | l1/fees BaseFeeRates fields (4f) RMP visit_str (0x23c4af0) | `research/work-items/RE-004-node115-fee-tiers-discounts/README.md` |
| `fees` | `0x36695a0..0x3669682` | 226 | 202/226 | 6 | l1/fees BaseFeeRates fields (4f) RMP visit_str (0x36695a0) | `research/work-items/RE-004-node115-fee-tiers-discounts/README.md` |
| `fees` | `0x51766a0..0x5176782` | 226 | 202/226 | 6 | l1/fees BaseFeeRates fields (4f) RMP visit_str (0x51766a0) | `research/work-items/RE-004-node115-fee-tiers-discounts/README.md` |
| `fees` | `0x23c4be0..0x23c4cda` | 250 | 227/250 | 6 | l1/fees BaseFeeRates fields (4f) JSON visit_str (0x23c4be0) | `research/work-items/RE-004-node115-fee-tiers-discounts/README.md` |
| `fees` | `0x36694a0..0x366959a` | 250 | 227/250 | 6 | l1/fees BaseFeeRates fields (4f) JSON visit_str (0x36694a0) | `research/work-items/RE-004-node115-fee-tiers-discounts/README.md` |
| `vaults` | `0x2881300..0x28813e2` | 226 | 214/226 | 3 | l1/vault CreateVaultAction fields (5f) RMP visit_str (0x2881300) | `research/work-items/RE-007-node115-vault-distribute-and-map/README.md` |
| `vaults` | `0x4691290..0x4691372` | 226 | 214/226 | 3 | l1/vault CreateVaultAction fields (5f) RMP visit_str (0x4691290) | `research/work-items/RE-007-node115-vault-distribute-and-map/README.md` |
| `vaults` | `0x5358f10..0x5358ff2` | 226 | 214/226 | 3 | l1/vault CreateVaultAction fields (5f) RMP visit_str (0x5358f10) | `research/work-items/RE-007-node115-vault-distribute-and-map/README.md` |
| `vaults` | `0x2881200..0x28812f8` | 248 | 237/248 | 3 | l1/vault CreateVaultAction fields (5f) JSON visit_str (0x2881200) | `research/work-items/RE-007-node115-vault-distribute-and-map/README.md` |
| `vaults` | `0x4691380..0x4691478` | 248 | 236/248 | 3 | l1/vault CreateVaultAction fields (5f) JSON visit_str (0x4691380) | `research/work-items/RE-007-node115-vault-distribute-and-map/README.md` |
| `action-wire` | `0x2d141d0..0x2d142b0` | 224 | 204/224 | 5 | l1/action ApproveAgentAction fields (5f) RMP visit_str (0x2d141d0) | `research/work-items/RE-010-action-type-matcher-115/README.md` |
| `action-wire` | `0x4459280..0x4459360` | 224 | 204/224 | 5 | l1/action ApproveAgentAction fields (5f) RMP visit_str (0x4459280) | `research/work-items/RE-010-action-type-matcher-115/README.md` |
| `action-wire` | `0x5359f50..0x535a030` | 224 | 204/224 | 5 | l1/action ApproveAgentAction fields (5f) RMP visit_str (0x5359f50) | `research/work-items/RE-010-action-type-matcher-115/README.md` |
| `action-wire` | `0x2d140d0..0x2d141c8` | 248 | 228/248 | 5 | l1/action ApproveAgentAction fields (5f) JSON visit_str (0x2d140d0) | `research/work-items/RE-010-action-type-matcher-115/README.md` |
| `action-wire` | `0x4459360..0x4459458` | 248 | 229/248 | 5 | l1/action ApproveAgentAction fields (5f) JSON visit_str (0x4459360) | `research/work-items/RE-010-action-type-matcher-115/README.md` |
| `dex-registry` | `0x2882d20..0x2882dff` | 223 | 211/223 | 3 | l1/dex_registry RegisterPerpAsset2 fields (5f) RMP visit_str (0x2882d20) | `research/work-items/RE-010-enum-variant-matchers-115/README.md` |
| `dex-registry` | `0x4692410..0x46924ef` | 223 | 211/223 | 3 | l1/dex_registry RegisterPerpAsset2 fields (5f) RMP visit_str (0x4692410) | `research/work-items/RE-010-enum-variant-matchers-115/README.md` |
| `dex-registry` | `0x5359a30..0x5359b0f` | 223 | 211/223 | 3 | l1/dex_registry RegisterPerpAsset2 fields (5f) RMP visit_str (0x5359a30) | `research/work-items/RE-010-enum-variant-matchers-115/README.md` |
| `dex-registry` | `0x2882e00..0x2882ef5` | 245 | 234/245 | 3 | l1/dex_registry RegisterPerpAsset2 fields (5f) JSON visit_str (0x2882e00) | `research/work-items/RE-010-enum-variant-matchers-115/README.md` |
| `dex-registry` | `0x46924f0..0x46925e5` | 245 | 233/245 | 3 | l1/dex_registry RegisterPerpAsset2 fields (5f) JSON visit_str (0x46924f0) | `research/work-items/RE-010-enum-variant-matchers-115/README.md` |
| `fees` | `0x23c7720..0x23c77fa` | 218 | 198/218 | 5 | l1/fees ApproveBuilderFeeAction fields (5f) RMP visit_str (0x23c7720) | `research/work-items/RE-004-node115-fee-tiers-discounts/README.md` |
| `fees` | `0x4461a20..0x4461afa` | 218 | 198/218 | 5 | l1/fees ApproveBuilderFeeAction fields (5f) RMP visit_str (0x4461a20) | `research/work-items/RE-004-node115-fee-tiers-discounts/README.md` |
| `fees` | `0x58dade0..0x58daeba` | 218 | 200/218 | 5 | l1/fees ApproveBuilderFeeAction fields (5f) RMP visit_str (0x58dade0) | `research/work-items/RE-004-node115-fee-tiers-discounts/README.md` |
| `fees` | `0x23c7800..0x23c78f2` | 242 | 223/242 | 5 | l1/fees ApproveBuilderFeeAction fields (5f) JSON visit_str (0x23c7800) | `research/work-items/RE-004-node115-fee-tiers-discounts/README.md` |
| `fees` | `0x4461920..0x4461a12` | 242 | 223/242 | 5 | l1/fees ApproveBuilderFeeAction fields (5f) JSON visit_str (0x4461920) | `research/work-items/RE-004-node115-fee-tiers-discounts/README.md` |
| `dex-registry` | `0x2882540..0x288261a` | 218 | 206/218 | 3 | l1/dex_registry RegisterPerpAsset fields (5f) RMP visit_str (0x2882540) | `research/work-items/RE-010-enum-variant-matchers-115/README.md` |
| `dex-registry` | `0x4691970..0x4691a4a` | 218 | 206/218 | 3 | l1/dex_registry RegisterPerpAsset fields (5f) RMP visit_str (0x4691970) | `research/work-items/RE-010-enum-variant-matchers-115/README.md` |
| `dex-registry` | `0x5359590..0x535966a` | 218 | 206/218 | 3 | l1/dex_registry RegisterPerpAsset fields (5f) RMP visit_str (0x5359590) | `research/work-items/RE-010-enum-variant-matchers-115/README.md` |
| `dex-registry` | `0x2882450..0x2882540` | 240 | 229/240 | 3 | l1/dex_registry RegisterPerpAsset fields (5f) JSON visit_str (0x2882450) | `research/work-items/RE-010-enum-variant-matchers-115/README.md` |
| `dex-registry` | `0x4691a50..0x4691b40` | 240 | 228/240 | 3 | l1/dex_registry RegisterPerpAsset fields (5f) JSON visit_str (0x4691a50) | `research/work-items/RE-010-enum-variant-matchers-115/README.md` |
| `action-wire` | `0x23bedd0..0x23beea5` | 213 | 194/213 | 5 | l1/action UsdSendAction fields (5f) RMP visit_str (0x23bedd0) | `research/work-items/RE-010-action-type-matcher-115/README.md` |
| `action-wire` | `0x4452850..0x4452925` | 213 | 195/213 | 5 | l1/action UsdSendAction fields (5f) RMP visit_str (0x4452850) | `research/work-items/RE-010-action-type-matcher-115/README.md` |
| `action-wire` | `0x58d7600..0x58d76d5` | 213 | 194/213 | 5 | l1/action UsdSendAction fields (5f) RMP visit_str (0x58d7600) | `research/work-items/RE-010-action-type-matcher-115/README.md` |
| `action-wire` | `0x23beeb0..0x23bef9d` | 237 | 218/237 | 5 | l1/action UsdSendAction fields (5f) JSON visit_str (0x23beeb0) | `research/work-items/RE-010-action-type-matcher-115/README.md` |
| `action-wire` | `0x4452760..0x445284d` | 237 | 220/237 | 5 | l1/action UsdSendAction fields (5f) JSON visit_str (0x4452760) | `research/work-items/RE-010-action-type-matcher-115/README.md` |
| `action-wire` | `0x23c8db0..0x23c8e82` | 210 | 190/210 | 5 | l1/action UserSetAbstractionAction fields (5f) RMP visit_str (0x23c8db0) | `research/work-items/RE-010-action-type-matcher-115/README.md` |
| `action-wire` | `0x44631e0..0x44632b2` | 210 | 190/210 | 5 | l1/action UserSetAbstractionAction fields (5f) RMP visit_str (0x44631e0) | `research/work-items/RE-010-action-type-matcher-115/README.md` |
| `action-wire` | `0x535c5e0..0x535c6b2` | 210 | 190/210 | 5 | l1/action UserSetAbstractionAction fields (5f) RMP visit_str (0x535c5e0) | `research/work-items/RE-010-action-type-matcher-115/README.md` |
| `action-wire` | `0x23c8cc0..0x23c8daa` | 234 | 215/234 | 5 | l1/action UserSetAbstractionAction fields (5f) JSON visit_str (0x23c8cc0) | `research/work-items/RE-010-action-type-matcher-115/README.md` |
| `action-wire` | `0x44630f0..0x44631da` | 234 | 215/234 | 5 | l1/action UserSetAbstractionAction fields (5f) JSON visit_str (0x44630f0) | `research/work-items/RE-010-action-type-matcher-115/README.md` |
| `bridge` | `0x288e2b0..0x288e382` | 210 | 198/210 | 3 | l1/bridge BridgeWithdrawalRequest fields (5f) RMP visit_str (0x288e2b0) | `research/work-items/bridge-contracts-and-state-layout-115/README.md` |
| `bridge` | `0x4465fc0..0x4466092` | 210 | 198/210 | 3 | l1/bridge BridgeWithdrawalRequest fields (5f) RMP visit_str (0x4465fc0) | `research/work-items/bridge-contracts-and-state-layout-115/README.md` |
| `bridge` | `0x58dc1f0..0x58dc2c2` | 210 | 199/210 | 3 | l1/bridge BridgeWithdrawalRequest fields (5f) RMP visit_str (0x58dc1f0) | `research/work-items/bridge-contracts-and-state-layout-115/README.md` |
| `bridge` | `0x288e1c0..0x288e2a9` | 233 | 222/233 | 3 | l1/bridge BridgeWithdrawalRequest fields (5f) JSON visit_str (0x288e1c0) | `research/work-items/bridge-contracts-and-state-layout-115/README.md` |
| `bridge` | `0x4465ed0..0x4465fb9` | 233 | 222/233 | 3 | l1/bridge BridgeWithdrawalRequest fields (5f) JSON visit_str (0x4465ed0) | `research/work-items/bridge-contracts-and-state-layout-115/README.md` |
| `bridge` | `0x288e970..0x288ea42` | 210 | 198/210 | 3 | l1/bridge BridgeDepositRequest fields (5f) RMP visit_str (0x288e970) | `research/work-items/bridge-contracts-and-state-layout-115/README.md` |
| `bridge` | `0x44667b0..0x4466882` | 210 | 198/210 | 3 | l1/bridge BridgeDepositRequest fields (5f) RMP visit_str (0x44667b0) | `research/work-items/bridge-contracts-and-state-layout-115/README.md` |
| `bridge` | `0x535d330..0x535d402` | 210 | 198/210 | 3 | l1/bridge BridgeDepositRequest fields (5f) RMP visit_str (0x535d330) | `research/work-items/bridge-contracts-and-state-layout-115/README.md` |
| `bridge` | `0x288ea50..0x288eb39` | 233 | 222/233 | 3 | l1/bridge BridgeDepositRequest fields (5f) JSON visit_str (0x288ea50) | `research/work-items/bridge-contracts-and-state-layout-115/README.md` |
| `bridge` | `0x44666c0..0x44667a9` | 233 | 222/233 | 3 | l1/bridge BridgeDepositRequest fields (5f) JSON visit_str (0x44666c0) | `research/work-items/bridge-contracts-and-state-layout-115/README.md` |
| `staking` | `0x2d14a40..0x2d14b0f` | 207 | 187/207 | 5 | l1/c_staking LinkStakingUserAction fields (5f) RMP visit_str (0x2d14a40) | `research/work-items/RE-008-node115-staking-crate-map/README.md` |
| `staking` | `0x445eb00..0x445ebcf` | 207 | 187/207 | 5 | l1/c_staking LinkStakingUserAction fields (5f) RMP visit_str (0x445eb00) | `research/work-items/RE-008-node115-staking-crate-map/README.md` |
| `staking` | `0x58d9dc0..0x58d9e8f` | 207 | 188/207 | 5 | l1/c_staking LinkStakingUserAction fields (5f) RMP visit_str (0x58d9dc0) | `research/work-items/RE-008-node115-staking-crate-map/README.md` |
| `staking` | `0x2d14b10..0x2d14bf7` | 231 | 212/231 | 5 | l1/c_staking LinkStakingUserAction fields (5f) JSON visit_str (0x2d14b10) | `research/work-items/RE-008-node115-staking-crate-map/README.md` |
| `staking` | `0x445ea10..0x445eaf7` | 231 | 214/231 | 5 | l1/c_staking LinkStakingUserAction fields (5f) JSON visit_str (0x445ea10) | `research/work-items/RE-008-node115-staking-crate-map/README.md` |
| `risk` | `0x288f630..0x288f6fe` | 206 | 198/206 | 2 | l1/clearinghouse PortfolioMarginLimits fields (7f) RMP visit_str (0x288f630) | `research/work-items/RE-007-node115-clearinghouse-margin-user-state/README.md` |
| `risk` | `0x4698f20..0x4698fee` | 206 | 198/206 | 2 | l1/clearinghouse PortfolioMarginLimits fields (7f) RMP visit_str (0x4698f20) | `research/work-items/RE-007-node115-clearinghouse-margin-user-state/README.md` |
| `risk` | `0x535dc20..0x535dcee` | 206 | 198/206 | 2 | l1/clearinghouse PortfolioMarginLimits fields (7f) RMP visit_str (0x535dc20) | `research/work-items/RE-007-node115-clearinghouse-margin-user-state/README.md` |
| `risk` | `0x288f700..0x288f7e4` | 228 | 221/228 | 2 | l1/clearinghouse PortfolioMarginLimits fields (7f) JSON visit_str (0x288f700) | `research/work-items/RE-007-node115-clearinghouse-margin-user-state/README.md` |
| `risk` | `0x4699160..0x4699244` | 228 | 220/228 | 2 | l1/clearinghouse PortfolioMarginLimits fields (7f) JSON visit_str (0x4699160) | `research/work-items/RE-007-node115-clearinghouse-margin-user-state/README.md` |
| `staking` | `0x23bfad0..0x23bfb75` | 165 | 149/165 | 4 | l1/c_staking CDepositAction fields (4f) RMP visit_str (0x23bfad0) | `research/work-items/RE-008-node115-staking-delegation/README.md` |
| `staking` | `0x4452dd0..0x4452e75` | 165 | 151/165 | 4 | l1/c_staking CDepositAction fields (4f) RMP visit_str (0x4452dd0) | `research/work-items/RE-008-node115-staking-delegation/README.md` |
| `staking` | `0x5354570..0x5354615` | 165 | 149/165 | 4 | l1/c_staking CDepositAction fields (4f) RMP visit_str (0x5354570) | `research/work-items/RE-008-node115-staking-delegation/README.md` |
| `staking` | `0x58d7a10..0x58d7ab5` | 165 | 150/165 | 4 | l1/c_staking CDepositAction fields (4f) RMP visit_str (0x58d7a10) | `research/work-items/RE-008-node115-staking-delegation/README.md` |
| `staking` | `0x23bfa10..0x23bface` | 190 | 175/190 | 4 | l1/c_staking CDepositAction fields (4f) JSON visit_str (0x23bfa10) | `research/work-items/RE-008-node115-staking-delegation/README.md` |
| `staking` | `0x4452e80..0x4452f3e` | 190 | 177/190 | 4 | l1/c_staking CDepositAction fields (4f) JSON visit_str (0x4452e80) | `research/work-items/RE-008-node115-staking-delegation/README.md` |
| `staking` | `0x23be6b0..0x23be776` | 198 | 178/198 | 5 | l1/governance GovVoteAction fields (5f) RMP visit_str (0x23be6b0) | `research/work-items/RE-008-node115-staking-delegation/README.md` |
| `staking` | `0x4452040..0x4452106` | 198 | 180/198 | 5 | l1/governance GovVoteAction fields (5f) RMP visit_str (0x4452040) | `research/work-items/RE-008-node115-staking-delegation/README.md` |
| `staking` | `0x58d7270..0x58d7336` | 198 | 179/198 | 5 | l1/governance GovVoteAction fields (5f) RMP visit_str (0x58d7270) | `research/work-items/RE-008-node115-staking-delegation/README.md` |
| `staking` | `0x23be780..0x23be85e` | 222 | 203/222 | 5 | l1/governance GovVoteAction fields (5f) JSON visit_str (0x23be780) | `research/work-items/RE-008-node115-staking-delegation/README.md` |
| `staking` | `0x4452110..0x44521ee` | 222 | 205/222 | 5 | l1/governance GovVoteAction fields (5f) JSON visit_str (0x4452110) | `research/work-items/RE-008-node115-staking-delegation/README.md` |
| `action-wire` | `0x23c85a0..0x23c8665` | 197 | 177/197 | 5 | l1/action UserDexAbstractionAction fields (5f) RMP visit_str (0x23c85a0) | `research/work-items/RE-010-action-type-matcher-115/README.md` |
| `action-wire` | `0x44629d0..0x4462a95` | 197 | 177/197 | 5 | l1/action UserDexAbstractionAction fields (5f) RMP visit_str (0x44629d0) | `research/work-items/RE-010-action-type-matcher-115/README.md` |
| `action-wire` | `0x58db150..0x58db215` | 197 | 178/197 | 5 | l1/action UserDexAbstractionAction fields (5f) RMP visit_str (0x58db150) | `research/work-items/RE-010-action-type-matcher-115/README.md` |
| `action-wire` | `0x23c8670..0x23c874d` | 221 | 202/221 | 5 | l1/action UserDexAbstractionAction fields (5f) JSON visit_str (0x23c8670) | `research/work-items/RE-010-action-type-matcher-115/README.md` |
| `action-wire` | `0x4462aa0..0x4462b7d` | 221 | 202/221 | 5 | l1/action UserDexAbstractionAction fields (5f) JSON visit_str (0x4462aa0) | `research/work-items/RE-010-action-type-matcher-115/README.md` |
| `action-wire` | `0x23c70c0..0x23c7184` | 196 | 180/196 | 4 | l1/action UsdClassTransferAction fields (5f) RMP visit_str (0x23c70c0) | `research/work-items/RE-010-action-type-matcher-115/README.md` |
| `action-wire` | `0x44609b0..0x4460a74` | 196 | 180/196 | 4 | l1/action UsdClassTransferAction fields (5f) RMP visit_str (0x44609b0) | `research/work-items/RE-010-action-type-matcher-115/README.md` |
| `action-wire` | `0x58da6b0..0x58da774` | 196 | 181/196 | 4 | l1/action UsdClassTransferAction fields (5f) RMP visit_str (0x58da6b0) | `research/work-items/RE-010-action-type-matcher-115/README.md` |
| `action-wire` | `0x23c6fe0..0x23c70bc` | 220 | 205/220 | 4 | l1/action UsdClassTransferAction fields (5f) JSON visit_str (0x23c6fe0) | `research/work-items/RE-010-action-type-matcher-115/README.md` |
| `action-wire` | `0x44608d0..0x44609ac` | 220 | 205/220 | 4 | l1/action UsdClassTransferAction fields (5f) JSON visit_str (0x44608d0) | `research/work-items/RE-010-action-type-matcher-115/README.md` |
| `vaults` | `0x288dd30..0x288ddee` | 190 | 178/190 | 3 | l1/vault SubAccountSpotTransferAction fields (4f) RMP visit_str (0x288dd30) | `research/work-items/RE-007-node115-vault-distribute-and-map/README.md` |
| `vaults` | `0x46980f0..0x46981ae` | 190 | 178/190 | 3 | l1/vault SubAccountSpotTransferAction fields (4f) RMP visit_str (0x46980f0) | `research/work-items/RE-007-node115-vault-distribute-and-map/README.md` |
| `vaults` | `0x535cd40..0x535cdfe` | 190 | 178/190 | 3 | l1/vault SubAccountSpotTransferAction fields (4f) RMP visit_str (0x535cd40) | `research/work-items/RE-007-node115-vault-distribute-and-map/README.md` |
| `vaults` | `0x288dc50..0x288dd24` | 212 | 201/212 | 3 | l1/vault SubAccountSpotTransferAction fields (4f) JSON visit_str (0x288dc50) | `research/work-items/RE-007-node115-vault-distribute-and-map/README.md` |
| `vaults` | `0x4698010..0x46980e4` | 212 | 200/212 | 3 | l1/vault SubAccountSpotTransferAction fields (4f) JSON visit_str (0x4698010) | `research/work-items/RE-007-node115-vault-distribute-and-map/README.md` |
| `risk` | `0x2745170..0x274522d` | 189 | 177/189 | 3 | l1/clearinghouse SetOracleAction fields (4f) RMP visit_str (0x2745170) | `research/work-items/RE-007-node115-clearinghouse-oracle-and-source-map/README.md` |
| `risk` | `0x3bd6950..0x3bd6a0d` | 189 | 177/189 | 3 | l1/clearinghouse SetOracleAction fields (4f) RMP visit_str (0x3bd6950) | `research/work-items/RE-007-node115-clearinghouse-oracle-and-source-map/README.md` |
| `risk` | `0x5354820..0x53548dd` | 189 | 177/189 | 3 | l1/clearinghouse SetOracleAction fields (4f) RMP visit_str (0x5354820) | `research/work-items/RE-007-node115-clearinghouse-oracle-and-source-map/README.md` |
| `risk` | `0x2745230..0x2745304` | 212 | 201/212 | 3 | l1/clearinghouse SetOracleAction fields (4f) JSON visit_str (0x2745230) | `research/work-items/RE-007-node115-clearinghouse-oracle-and-source-map/README.md` |
| `risk` | `0x3bd6a10..0x3bd6ae4` | 212 | 201/212 | 3 | l1/clearinghouse SetOracleAction fields (4f) JSON visit_str (0x3bd6a10) | `research/work-items/RE-007-node115-clearinghouse-oracle-and-source-map/README.md` |
| `staking` | `0x2d136b0..0x2d13769` | 185 | 161/185 | 6 | l1/c_staking LongTermStakingAction fields (4f) RMP visit_str (0x2d136b0) | `research/work-items/RE-008-node115-staking-withdrawal-queue/README.md` |
| `staking` | `0x4456960..0x4456a19` | 185 | 161/185 | 6 | l1/c_staking LongTermStakingAction fields (4f) RMP visit_str (0x4456960) | `research/work-items/RE-008-node115-staking-withdrawal-queue/README.md` |
| `staking` | `0x58d9070..0x58d9129` | 185 | 162/185 | 6 | l1/c_staking LongTermStakingAction fields (4f) RMP visit_str (0x58d9070) | `research/work-items/RE-008-node115-staking-withdrawal-queue/README.md` |
| `staking` | `0x2d135d0..0x2d136a2` | 210 | 186/210 | 6 | l1/c_staking LongTermStakingAction fields (4f) JSON visit_str (0x2d135d0) | `research/work-items/RE-008-node115-staking-withdrawal-queue/README.md` |
| `staking` | `0x4456a20..0x4456af2` | 210 | 187/210 | 6 | l1/c_staking LongTermStakingAction fields (4f) JSON visit_str (0x4456a20) | `research/work-items/RE-008-node115-staking-withdrawal-queue/README.md` |
| `staking` | `0x2d159b0..0x2d15a61` | 177 | 162/177 | 4 | l1/c_staking LinkTradingUserAction fields (4f) RMP visit_str (0x2d159b0) | `research/work-items/RE-008-node115-staking-crate-map/README.md` |
| `staking` | `0x4467000..0x44670b1` | 177 | 161/177 | 4 | l1/c_staking LinkTradingUserAction fields (4f) RMP visit_str (0x4467000) | `research/work-items/RE-008-node115-staking-crate-map/README.md` |
| `staking` | `0x58dc6f0..0x58dc7a1` | 177 | 162/177 | 4 | l1/c_staking LinkTradingUserAction fields (4f) RMP visit_str (0x58dc6f0) | `research/work-items/RE-008-node115-staking-crate-map/README.md` |
| `staking` | `0x2d15a70..0x2d15b39` | 201 | 185/201 | 4 | l1/c_staking LinkTradingUserAction fields (4f) JSON visit_str (0x2d15a70) | `research/work-items/RE-008-node115-staking-crate-map/README.md` |
| `staking` | `0x4466f30..0x4466ff9` | 201 | 186/201 | 4 | l1/c_staking LinkTradingUserAction fields (4f) JSON visit_str (0x4466f30) | `research/work-items/RE-008-node115-staking-crate-map/README.md` |
| `exchange` | `0x23ca4e0..0x23ca584` | 164 | 148/164 | 4 | l1/exchange ConvertToMultiSigUserAction fields (4f) RMP visit_str (0x23ca4e0) | `research/work-items/RE-010-action-type-matcher-115/README.md` |
| `exchange` | `0x44652e0..0x4465384` | 164 | 148/164 | 4 | l1/exchange ConvertToMultiSigUserAction fields (4f) RMP visit_str (0x44652e0) | `research/work-items/RE-010-action-type-matcher-115/README.md` |
| `exchange` | `0x58dbe00..0x58dbea4` | 164 | 149/164 | 4 | l1/exchange ConvertToMultiSigUserAction fields (4f) RMP visit_str (0x58dbe00) | `research/work-items/RE-010-action-type-matcher-115/README.md` |
| `exchange` | `0x23ca590..0x23ca64c` | 188 | 173/188 | 4 | l1/exchange ConvertToMultiSigUserAction fields (4f) JSON visit_str (0x23ca590) | `research/work-items/RE-010-action-type-matcher-115/README.md` |
| `exchange` | `0x4465390..0x446544c` | 188 | 173/188 | 4 | l1/exchange ConvertToMultiSigUserAction fields (4f) JSON visit_str (0x4465390) | `research/work-items/RE-010-action-type-matcher-115/README.md` |
| `staking` | `0x2890560..0x28905ea` | 138 | 130/138 | 2 | l1/c_staking CValidatorRegister fields (3f) RMP visit_str (0x2890560) | `research/work-items/RE-008-node115-staking-crate-map/README.md` |
| `staking` | `0x4467d60..0x4467dea` | 138 | 130/138 | 2 | l1/c_staking CValidatorRegister fields (3f) RMP visit_str (0x4467d60) | `research/work-items/RE-008-node115-staking-crate-map/README.md` |
| `staking` | `0x535e330..0x535e3ba` | 138 | 130/138 | 2 | l1/c_staking CValidatorRegister fields (3f) RMP visit_str (0x535e330) | `research/work-items/RE-008-node115-staking-crate-map/README.md` |
| `assets` | `0x3c4b280..0x3c4b30c` | 140 | 132/140 | 2 | l1/spot_meta TokenSpec::wei_per_sz (0x3c4b280) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `assets` | `0x3c47660..0x3c4769a` | 58 | 50/58 | 2 | l1/spot_meta SpotMeta::first_spot_for_token (0x3c47660) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `assets` | `0x3c47ae0..0x3c47b59` | 121 | 105/121 | 4 | l1/spot_meta SpotMeta::spot_for_quote (0x3c47ae0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `assets` | `0x3d1a2c0..0x3d1a314` | 84 | 68/84 | 4 | l1/spot_meta SpotMeta::quote_name_pair (0x3d1a2c0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `assets` | `0x3c4b1a0..0x3c4b274` | 212 | 196/212 | 4 | l1/spot_meta SpotMeta::checked_sz_to_wei (0x3c4b1a0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `assets` | `0x3d19800..0x3d19868` | 104 | 88/104 | 4 | l1/perp_meta PerpMeta::px_decimals (0x3d19800) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `assets` | `0x50beb30..0x50bebba` | 138 | 118/138 | 5 | l1/perp_meta PerpMeta::sz_to_f64 (0x50beb30) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `assets` | `0x50bea90..0x50beb2f` | 159 | 131/159 | 7 | l1/perp_meta PerpMeta::px_to_f64 (0x50bea90) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `exchange` | `0x24209c0..0x24209d9` | 25 | 21/25 | 1 | serde Visitor::expecting (enum AbstractionReturn) (0x24209c0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `exchange` | `0x3c4d550..0x3c4d569` | 25 | 21/25 | 1 | serde Visitor::expecting (enum AbstractionReturn) (0x3c4d550) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `exchange` | `0x4d9c310..0x4d9c329` | 25 | 21/25 | 1 | serde Visitor::expecting (enum AbstractionReturn) (0x4d9c310) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `constants` | `0x46ddb50..0x46ddb69` | 25 | 21/25 | 1 | serde Visitor::expecting (enum Chain) (0x46ddb50) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `constants` | `0x57d1bb0..0x57d1bc9` | 25 | 21/25 | 1 | serde Visitor::expecting (enum Chain) (0x57d1bb0) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `evm` | `0x22f5840..0x22f5859` | 25 | 21/25 | 1 | serde Visitor::expecting (enum EvmBlockWire) (0x22f5840) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `evm` | `0x44dc990..0x44dc9a9` | 25 | 21/25 | 1 | serde Visitor::expecting (enum EvmBlockWire) (0x44dc990) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `evm` | `0x5b08f50..0x5b08f69` | 25 | 21/25 | 1 | serde Visitor::expecting (enum EvmBlockWire) (0x5b08f50) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `storage` | `0x25eb7c0..0x25eb7d9` | 25 | 21/25 | 1 | serde Visitor::expecting (enum EvmDbSerde) (0x25eb7c0) | `research/work-items/RE-009-node115-storage-abci-byte-matches/README.md` |
| `storage` | `0x38db780..0x38db799` | 25 | 21/25 | 1 | serde Visitor::expecting (enum EvmDbSerde) (0x38db780) | `research/work-items/RE-009-node115-storage-abci-byte-matches/README.md` |
| `storage` | `0x50d93e0..0x50d93f9` | 25 | 21/25 | 1 | serde Visitor::expecting (enum EvmDbSerde) (0x50d93e0) | `research/work-items/RE-009-node115-storage-abci-byte-matches/README.md` |
| `risk` | `0x25eb590..0x25eb5a9` | 25 | 21/25 | 1 | serde Visitor::expecting (enum Leverage) (0x25eb590) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `risk` | `0x4229220..0x4229239` | 25 | 21/25 | 1 | serde Visitor::expecting (enum Leverage) (0x4229220) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `risk` | `0x5b097d0..0x5b097e9` | 25 | 21/25 | 1 | serde Visitor::expecting (enum Leverage) (0x5b097d0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `dex-registry` | `0x2c7ce10..0x2c7ce29` | 25 | 21/25 | 1 | serde Visitor::expecting (enum MainOrHip3) (0x2c7ce10) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `dex-registry` | `0x44dc970..0x44dc989` | 25 | 21/25 | 1 | serde Visitor::expecting (enum MainOrHip3) (0x44dc970) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `dex-registry` | `0x5616a50..0x5616a69` | 25 | 21/25 | 1 | serde Visitor::expecting (enum MainOrHip3) (0x5616a50) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `transport` | `0x26a18b0..0x26a18c9` | 25 | 21/25 | 1 | serde Visitor::expecting (enum NodeIp) (0x26a18b0) | `research/work-items/RE-012-node115-gossip-rpc-connections-local-state/README.md` |
| `transport` | `0x4229080..0x4229099` | 25 | 21/25 | 1 | serde Visitor::expecting (enum NodeIp) (0x4229080) | `research/work-items/RE-012-node115-gossip-rpc-connections-local-state/README.md` |
| `transport` | `0x5a2f1f0..0x5a2f209` | 25 | 21/25 | 1 | serde Visitor::expecting (enum NodeIp) (0x5a2f1f0) | `research/work-items/RE-012-node115-gossip-rpc-connections-local-state/README.md` |
| `risk` | `0x22f5b60..0x22f5b79` | 25 | 21/25 | 1 | serde Visitor::expecting (enum OracleKind) (0x22f5b60) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `risk` | `0x3d52920..0x3d52939` | 25 | 21/25 | 1 | serde Visitor::expecting (enum OracleKind) (0x3d52920) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `risk` | `0x53d6070..0x53d6089` | 25 | 21/25 | 1 | serde Visitor::expecting (enum OracleKind) (0x53d6070) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `orderbook` | `0x25ebb10..0x25ebb29` | 25 | 21/25 | 1 | serde Visitor::expecting (enum OrderDescription) (0x25ebb10) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x44dc4f0..0x44dc509` | 25 | 21/25 | 1 | serde Visitor::expecting (enum OrderDescription) (0x44dc4f0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x51ad680..0x51ad699` | 25 | 21/25 | 1 | serde Visitor::expecting (enum OrderDescription) (0x51ad680) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `abci` | `0x292c9d0..0x292c9e9` | 25 | 21/25 | 1 | serde Visitor::expecting (enum QuorumStatus) (0x292c9d0) | `research/work-items/RE-009-node115-storage-abci-byte-matches/README.md` |
| `abci` | `0x36cd050..0x36cd069` | 25 | 22/25 | 1 | serde Visitor::expecting (enum QuorumStatus) (0x36cd050) | `research/work-items/RE-009-node115-storage-abci-byte-matches/README.md` |
| `abci` | `0x53d5d70..0x53d5d89` | 25 | 21/25 | 1 | serde Visitor::expecting (enum QuorumStatus) (0x53d5d70) | `research/work-items/RE-009-node115-storage-abci-byte-matches/README.md` |
| `evm` | `0x26a1c20..0x26a1c39` | 25 | 21/25 | 1 | serde Visitor::expecting (enum ReadPrecompileResult) (0x26a1c20) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `risk` | `0x25eb510..0x25eb529` | 25 | 21/25 | 1 | serde Visitor::expecting (enum ReferenceOracleKey) (0x25eb510) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `risk` | `0x36cd030..0x36cd049` | 25 | 22/25 | 1 | serde Visitor::expecting (enum ReferenceOracleKey) (0x36cd030) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `risk` | `0x50d9640..0x50d9659` | 25 | 21/25 | 1 | serde Visitor::expecting (enum ReferenceOracleKey) (0x50d9640) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `assets` | `0x26a14b0..0x26a14c9` | 25 | 21/25 | 1 | serde Visitor::expecting (enum Side) (0x26a14b0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `assets` | `0x3d527b0..0x3d527c9` | 25 | 21/25 | 1 | serde Visitor::expecting (enum Side) (0x3d527b0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `assets` | `0x57d1b10..0x57d1b29` | 25 | 21/25 | 1 | serde Visitor::expecting (enum Side) (0x57d1b10) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x2420430..0x2420449` | 25 | 21/25 | 1 | serde Visitor::expecting (enum Tpsl) (0x2420430) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x44dc9b0..0x44dc9c9` | 25 | 21/25 | 1 | serde Visitor::expecting (enum Tpsl) (0x44dc9b0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x5a2f130..0x5a2f149` | 25 | 21/25 | 1 | serde Visitor::expecting (enum Tpsl) (0x5a2f130) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `serialization` | `0x22f5c20..0x22f5c39` | 25 | 21/25 | 1 | serde Visitor::expecting (enum TransactionWire) (0x22f5c20) | `research/work-items/RE-012-node115-artifact-and-stream-msg/README.md` |
| `serialization` | `0x44dc0f0..0x44dc109` | 25 | 21/25 | 1 | serde Visitor::expecting (enum TransactionWire) (0x44dc0f0) | `research/work-items/RE-012-node115-artifact-and-stream-msg/README.md` |
| `serialization` | `0x5b09810..0x5b09829` | 25 | 21/25 | 1 | serde Visitor::expecting (enum TransactionWire) (0x5b09810) | `research/work-items/RE-012-node115-artifact-and-stream-msg/README.md` |
| `evm` | `0x22f5b00..0x22f5b19` | 25 | 21/25 | 1 | serde Visitor::expecting (enum TxTypeWire) (0x22f5b00) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `orderbook` | `0x24203d0..0x24203e9` | 25 | 21/25 | 1 | serde Visitor::expecting (enum UntriggeredOrder) (0x24203d0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x38dbc00..0x38dbc19` | 25 | 21/25 | 1 | serde Visitor::expecting (enum UntriggeredOrder) (0x38dbc00) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x5941d50..0x5941d69` | 25 | 21/25 | 1 | serde Visitor::expecting (enum UntriggeredOrder) (0x5941d50) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `exchange` | `0x2420610..0x2420629` | 25 | 21/25 | 1 | serde Visitor::expecting (enum UserAbstraction) (0x2420610) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `exchange` | `0x3c4d770..0x3c4d789` | 25 | 21/25 | 1 | serde Visitor::expecting (enum UserAbstraction) (0x3c4d770) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `exchange` | `0x4d9c210..0x4d9c229` | 25 | 21/25 | 1 | serde Visitor::expecting (enum UserAbstraction) (0x4d9c210) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `vaults` | `0x292cfd0..0x292cfe9` | 25 | 21/25 | 1 | serde Visitor::expecting (enum VaultSpotMode) (0x292cfd0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `vaults` | `0x44dcb70..0x44dcb89` | 25 | 21/25 | 1 | serde Visitor::expecting (enum VaultSpotMode) (0x44dcb70) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `vaults` | `0x4d9c4f0..0x4d9c509` | 25 | 21/25 | 1 | serde Visitor::expecting (enum VaultSpotMode) (0x4d9c4f0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `abci` | `0x22f5c60..0x22f5c79` | 25 | 21/25 | 1 | serde Visitor::expecting (struct AbciStateDe) (0x22f5c60) | `research/work-items/RE-009-node115-storage-abci-byte-matches/README.md` |
| `abci` | `0x3c4d7b0..0x3c4d7c9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct AbciStateDe) (0x3c4d7b0) | `research/work-items/RE-009-node115-storage-abci-byte-matches/README.md` |
| `abci` | `0x5616dd0..0x5616de9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct AbciStateDe) (0x5616dd0) | `research/work-items/RE-009-node115-storage-abci-byte-matches/README.md` |
| `exchange` | `0x2420450..0x2420469` | 25 | 21/25 | 1 | serde Visitor::expecting (struct AbstractionCounters) (0x2420450) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `exchange` | `0x3c4d870..0x3c4d889` | 25 | 21/25 | 1 | serde Visitor::expecting (struct AbstractionCounters) (0x3c4d870) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `exchange` | `0x4d9c020..0x4d9c039` | 25 | 21/25 | 1 | serde Visitor::expecting (struct AbstractionCounters) (0x4d9c020) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `fees` | `0x292d310..0x292d329` | 25 | 21/25 | 1 | serde Visitor::expecting (struct AddCrossScaledVlm) (0x292d310) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `fees` | `0x36cd1d0..0x36cd1e9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct AddCrossScaledVlm) (0x36cd1d0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `fees` | `0x4d9c9c0..0x4d9c9d9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct AddCrossScaledVlm) (0x4d9c9c0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `action-wire` | `0x24204f0..0x2420509` | 25 | 21/25 | 1 | serde Visitor::expecting (struct ApproveBuilderFeeAction) (0x24204f0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `action-wire` | `0x445f500..0x445f519` | 25 | 21/25 | 1 | serde Visitor::expecting (struct ApproveBuilderFeeAction) (0x445f500) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `action-wire` | `0x5941e50..0x5941e69` | 25 | 21/25 | 1 | serde Visitor::expecting (struct ApproveBuilderFeeAction) (0x5941e50) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `assets` | `0x292dd10..0x292dd29` | 25 | 21/25 | 1 | serde Visitor::expecting (struct Aqav2TokenInfo) (0x292dd10) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `assets` | `0x3c4d130..0x3c4d149` | 25 | 21/25 | 1 | serde Visitor::expecting (struct Aqav2TokenInfo) (0x3c4d130) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `assets` | `0x5a2f350..0x5a2f369` | 25 | 21/25 | 1 | serde Visitor::expecting (struct Aqav2TokenInfo) (0x5a2f350) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `action-wire` | `0x2d4a610..0x2d4a629` | 25 | 21/25 | 1 | serde Visitor::expecting (struct BatchModifyAction) (0x2d4a610) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `action-wire` | `0x41fe700..0x41fe719` | 25 | 21/25 | 1 | serde Visitor::expecting (struct BatchModifyAction) (0x41fe700) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `action-wire` | `0x51ad7c0..0x51ad7d9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct BatchModifyAction) (0x51ad7c0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `evm` | `0x22f5940..0x22f5959` | 25 | 21/25 | 1 | serde Visitor::expecting (struct BlockBodyWire) (0x22f5940) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `evm` | `0x44dc6b0..0x44dc6c9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct BlockBodyWire) (0x44dc6b0) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `evm` | `0x5b097f0..0x5b09809` | 25 | 21/25 | 1 | serde Visitor::expecting (struct BlockBodyWire) (0x5b097f0) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `orderbook` | `0x2420980..0x2420999` | 25 | 21/25 | 1 | serde Visitor::expecting (struct Book) (0x2420980) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x38dbc60..0x38dbc79` | 25 | 21/25 | 1 | serde Visitor::expecting (struct Book) (0x38dbc60) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x5941f50..0x5941f69` | 25 | 21/25 | 1 | serde Visitor::expecting (struct Book) (0x5941f50) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x25eb8e0..0x25eb8f9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct BookOrder) (0x25eb8e0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x44dc110..0x44dc129` | 25 | 21/25 | 1 | serde Visitor::expecting (struct BookOrder) (0x44dc110) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x51ad390..0x51ad3a9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct BookOrder) (0x51ad390) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `bridge` | `0x292c7b0..0x292c7c9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct Bridge2) (0x292c7b0) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `bridge` | `0x44dc450..0x44dc469` | 25 | 21/25 | 1 | serde Visitor::expecting (struct Bridge2) (0x44dc450) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `bridge` | `0x5b094b0..0x5b094c9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct Bridge2) (0x5b094b0) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `bridge` | `0x2420a20..0x2420a39` | 25 | 21/25 | 1 | serde Visitor::expecting (struct BridgeValidatorSet) (0x2420a20) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `bridge` | `0x36cd0d0..0x36cd0e9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct BridgeValidatorSet) (0x36cd0d0) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `bridge` | `0x51adc90..0x51adca9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct BridgeValidatorSet) (0x51adc90) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `orderbook` | `0x25ebb30..0x25ebb49` | 25 | 21/25 | 1 | serde Visitor::expecting (struct Cancel) (0x25ebb30) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x3bcfab0..0x3bcfac9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct Cancel) (0x3bcfab0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x51adc70..0x51adc89` | 25 | 21/25 | 1 | serde Visitor::expecting (struct Cancel) (0x51adc70) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `action-wire` | `0x25eb550..0x25eb569` | 25 | 21/25 | 1 | serde Visitor::expecting (struct CancelAction) (0x25eb550) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `action-wire` | `0x3bd13a0..0x3bd13b9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct CancelAction) (0x3bd13a0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `action-wire` | `0x51ad4f0..0x51ad509` | 25 | 21/25 | 1 | serde Visitor::expecting (struct CancelAction) (0x51ad4f0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `orderbook` | `0x25eb840..0x25eb859` | 25 | 21/25 | 1 | serde Visitor::expecting (struct CancelByCloid) (0x25eb840) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x468ded0..0x468dee9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct CancelByCloid) (0x468ded0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x51ad620..0x51ad639` | 25 | 21/25 | 1 | serde Visitor::expecting (struct CancelByCloid) (0x51ad620) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `action-wire` | `0x25eb6a0..0x25eb6b9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct CancelByCloidAction) (0x25eb6a0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `action-wire` | `0x46929b0..0x46929c9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct CancelByCloidAction) (0x46929b0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `action-wire` | `0x51adc30..0x51adc49` | 25 | 21/25 | 1 | serde Visitor::expecting (struct CancelByCloidAction) (0x51adc30) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `risk` | `0x2773db0..0x2773dc9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct Clearinghouse) (0x2773db0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `risk` | `0x44dc310..0x44dc329` | 25 | 21/25 | 1 | serde Visitor::expecting (struct Clearinghouse) (0x44dc310) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `risk` | `0x5b09070..0x5b09089` | 25 | 21/25 | 1 | serde Visitor::expecting (struct Clearinghouse) (0x5b09070) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `orderbook` | `0x2773dd0..0x2773de9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct CloidTracker) (0x2773dd0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x43512e0..0x43512f9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct CloidTracker) (0x43512e0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x4d9ca60..0x4d9ca79` | 25 | 21/25 | 1 | serde Visitor::expecting (struct CloidTracker) (0x4d9ca60) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `abci` | `0x57d1970..0x57d1989` | 25 | 21/25 | 1 | serde Visitor::expecting (struct ColdQuorumL1Hash) (0x57d1970) | `research/work-items/RE-009-node115-storage-abci-byte-matches/README.md` |
| `action-wire` | `0x24201e0..0x24201f9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct ConvertToMultiSigUserAction) (0x24201e0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `action-wire` | `0x4464a90..0x4464aa9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct ConvertToMultiSigUserAction) (0x4464a90) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `action-wire` | `0x59423b0..0x59423c9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct ConvertToMultiSigUserAction) (0x59423b0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `vaults` | `0x292db90..0x292dba9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct CreateSubAccountAction) (0x292db90) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `vaults` | `0x46955f0..0x4695609` | 25 | 21/25 | 1 | serde Visitor::expecting (struct CreateSubAccountAction) (0x46955f0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `vaults` | `0x53d67f0..0x53d6809` | 25 | 21/25 | 1 | serde Visitor::expecting (struct CreateSubAccountAction) (0x53d67f0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `vaults` | `0x292c8f0..0x292c909` | 25 | 21/25 | 1 | serde Visitor::expecting (struct CreateVaultAction) (0x292c8f0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `vaults` | `0x468cdf0..0x468ce09` | 25 | 21/25 | 1 | serde Visitor::expecting (struct CreateVaultAction) (0x468cdf0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `vaults` | `0x53d6770..0x53d6789` | 25 | 21/25 | 1 | serde Visitor::expecting (struct CreateVaultAction) (0x53d6770) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `storage` | `0x38dba40..0x38dba59` | 25 | 21/25 | 1 | serde Visitor::expecting (struct DbAccountInfo) (0x38dba40) | `research/work-items/RE-009-node115-storage-abci-byte-matches/README.md` |
| `bridge` | `0x292d810..0x292d829` | 25 | 21/25 | 1 | serde Visitor::expecting (struct EthEventId) (0x292d810) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `bridge` | `0x44dc890..0x44dc8a9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct EthEventId) (0x44dc890) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `bridge` | `0x5b09750..0x5b09769` | 25 | 21/25 | 1 | serde Visitor::expecting (struct EthEventId) (0x5b09750) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `evm-rpc` | `0x17577c0..0x17577d9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct EvmRpcConfig) (0x17577c0) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `evm` | `0x2773790..0x27737a9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct EvmState) (0x2773790) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `evm` | `0x4351420..0x4351439` | 25 | 21/25 | 1 | serde Visitor::expecting (struct EvmState) (0x4351420) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `evm` | `0x51ad940..0x51ad959` | 25 | 21/25 | 1 | serde Visitor::expecting (struct EvmState) (0x51ad940) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `evm` | `0x22f5c40..0x22f5c59` | 25 | 21/25 | 1 | serde Visitor::expecting (struct EvmTxLookup) (0x22f5c40) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `evm` | `0x5b08f10..0x5b08f29` | 25 | 21/25 | 1 | serde Visitor::expecting (struct EvmTxLookup) (0x5b08f10) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `evm` | `0x292ca70..0x292ca89` | 25 | 21/25 | 1 | serde Visitor::expecting (struct EvmUserModifyAction) (0x292ca70) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `evm` | `0x46929d0..0x46929e9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct EvmUserModifyAction) (0x46929d0) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `evm` | `0x53d6550..0x53d6569` | 25 | 21/25 | 1 | serde Visitor::expecting (struct EvmUserModifyAction) (0x53d6550) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `exchange` | `0x2c7d1f0..0x2c7d209` | 25 | 21/25 | 1 | serde Visitor::expecting (struct Exchange) (0x2c7d1f0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `exchange` | `0x3c4d850..0x3c4d869` | 25 | 21/25 | 1 | serde Visitor::expecting (struct Exchange) (0x3c4d850) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `exchange` | `0x5616950..0x5616969` | 25 | 21/25 | 1 | serde Visitor::expecting (struct Exchange) (0x5616950) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `exchange` | `0x2c7d490..0x2c7d4a9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct ExchangeCounters) (0x2c7d490) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `exchange` | `0x3c4d2d0..0x3c4d2e9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct ExchangeCounters) (0x3c4d2d0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `exchange` | `0x5616d10..0x5616d29` | 25 | 21/25 | 1 | serde Visitor::expecting (struct ExchangeCounters) (0x5616d10) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `exchange` | `0x2c7d350..0x2c7d369` | 25 | 21/25 | 1 | serde Visitor::expecting (struct ExchangeMisc) (0x2c7d350) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `exchange` | `0x3c4d030..0x3c4d049` | 25 | 21/25 | 1 | serde Visitor::expecting (struct ExchangeMisc) (0x3c4d030) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `exchange` | `0x56164b0..0x56164c9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct ExchangeMisc) (0x56164b0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `fees` | `0x2773e70..0x2773e89` | 25 | 21/25 | 1 | serde Visitor::expecting (struct FeeSchedule) (0x2773e70) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `fees` | `0x36cd1f0..0x36cd209` | 25 | 21/25 | 1 | serde Visitor::expecting (struct FeeSchedule) (0x36cd1f0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `fees` | `0x5616c10..0x5616c29` | 25 | 21/25 | 1 | serde Visitor::expecting (struct FeeSchedule) (0x5616c10) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `fees` | `0x2773710..0x2773729` | 25 | 21/25 | 1 | serde Visitor::expecting (struct FeeTiers) (0x2773710) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `fees` | `0x36cd150..0x36cd169` | 25 | 21/25 | 1 | serde Visitor::expecting (struct FeeTiers) (0x36cd150) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `fees` | `0x5616b30..0x5616b49` | 25 | 21/25 | 1 | serde Visitor::expecting (struct FeeTiers) (0x5616b30) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `fees` | `0x292cd70..0x292cd89` | 25 | 21/25 | 1 | serde Visitor::expecting (struct FeeTracker) (0x292cd70) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `fees` | `0x3c4d5f0..0x3c4d609` | 25 | 21/25 | 1 | serde Visitor::expecting (struct FeeTracker) (0x3c4d5f0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `fees` | `0x5616490..0x56164a9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct FeeTracker) (0x5616490) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `fees` | `0x292dc50..0x292dc69` | 25 | 21/25 | 1 | serde Visitor::expecting (struct FeeTrial) (0x292dc50) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `fees` | `0x3c4d2b0..0x3c4d2c9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct FeeTrial) (0x3c4d2b0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `fees` | `0x5616a70..0x5616a89` | 25 | 21/25 | 1 | serde Visitor::expecting (struct FeeTrial) (0x5616a70) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `transport` | `0x292c890..0x292c8a9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct GossipPriorityBidAction) (0x292c890) | `research/work-items/RE-012-node115-gossip-rpc-connections-local-state/README.md` |
| `transport` | `0x445f520..0x445f539` | 25 | 21/25 | 1 | serde Visitor::expecting (struct GossipPriorityBidAction) (0x445f520) | `research/work-items/RE-012-node115-gossip-rpc-connections-local-state/README.md` |
| `transport` | `0x53d6970..0x53d6989` | 25 | 21/25 | 1 | serde Visitor::expecting (struct GossipPriorityBidAction) (0x53d6970) | `research/work-items/RE-012-node115-gossip-rpc-connections-local-state/README.md` |
| `transport` | `0x292d930..0x292d949` | 25 | 21/25 | 1 | serde Visitor::expecting (struct GossipPriorityGasAuction) (0x292d930) | `research/work-items/RE-012-node115-gossip-rpc-connections-local-state/README.md` |
| `transport` | `0x4229200..0x4229219` | 25 | 21/25 | 1 | serde Visitor::expecting (struct GossipPriorityGasAuction) (0x4229200) | `research/work-items/RE-012-node115-gossip-rpc-connections-local-state/README.md` |
| `transport` | `0x53d5b70..0x53d5b89` | 25 | 21/25 | 1 | serde Visitor::expecting (struct GossipPriorityGasAuction) (0x53d5b70) | `research/work-items/RE-012-node115-gossip-rpc-connections-local-state/README.md` |
| `abci` | `0x27737d0..0x27737e9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct HardforkHashTracker) (0x27737d0) | `research/work-items/RE-009-node115-storage-abci-byte-matches/README.md` |
| `abci` | `0x4229100..0x4229119` | 25 | 21/25 | 1 | serde Visitor::expecting (struct HardforkHashTracker) (0x4229100) | `research/work-items/RE-009-node115-storage-abci-byte-matches/README.md` |
| `abci` | `0x5b094d0..0x5b094e9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct HardforkHashTracker) (0x5b094d0) | `research/work-items/RE-009-node115-storage-abci-byte-matches/README.md` |
| `abci` | `0x27731b0..0x27731c9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct HashHardQuorum) (0x27731b0) | `research/work-items/RE-009-node115-storage-abci-byte-matches/README.md` |
| `abci` | `0x4229120..0x4229139` | 25 | 21/25 | 1 | serde Visitor::expecting (struct HashHardQuorum) (0x4229120) | `research/work-items/RE-009-node115-storage-abci-byte-matches/README.md` |
| `abci` | `0x5b09050..0x5b09069` | 25 | 21/25 | 1 | serde Visitor::expecting (struct HashHardQuorum) (0x5b09050) | `research/work-items/RE-009-node115-storage-abci-byte-matches/README.md` |
| `abci` | `0x2773b90..0x2773ba9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct HashSignatureTracker) (0x2773b90) | `research/work-items/RE-009-node115-storage-abci-byte-matches/README.md` |
| `abci` | `0x4228f10..0x4228f29` | 25 | 21/25 | 1 | serde Visitor::expecting (struct HashSignatureTracker) (0x4228f10) | `research/work-items/RE-009-node115-storage-abci-byte-matches/README.md` |
| `abci` | `0x5b09030..0x5b09049` | 25 | 21/25 | 1 | serde Visitor::expecting (struct HashSignatureTracker) (0x5b09030) | `research/work-items/RE-009-node115-storage-abci-byte-matches/README.md` |
| `dex-registry` | `0x2c7cf90..0x2c7cfa9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct Hip3BackstopLiquidatorParams) (0x2c7cf90) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `dex-registry` | `0x44dc610..0x44dc629` | 25 | 21/25 | 1 | serde Visitor::expecting (struct Hip3BackstopLiquidatorParams) (0x44dc610) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `dex-registry` | `0x56167b0..0x56167c9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct Hip3BackstopLiquidatorParams) (0x56167b0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `dex-registry` | `0x2773950..0x2773969` | 25 | 21/25 | 1 | serde Visitor::expecting (struct Hip3BackstopLiquidatorState) (0x2773950) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `dex-registry` | `0x4351400..0x4351419` | 25 | 21/25 | 1 | serde Visitor::expecting (struct Hip3BackstopLiquidatorState) (0x4351400) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `dex-registry` | `0x53d6050..0x53d6069` | 25 | 21/25 | 1 | serde Visitor::expecting (struct Hip3BackstopLiquidatorState) (0x53d6050) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `dex-registry` | `0x2c7ced0..0x2c7cee9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct Hip3DeployerFee) (0x2c7ced0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `dex-registry` | `0x44dcd30..0x44dcd49` | 25 | 21/25 | 1 | serde Visitor::expecting (struct Hip3DeployerFee) (0x44dcd30) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `dex-registry` | `0x56169b0..0x56169c9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct Hip3DeployerFee) (0x56169b0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `dex-registry` | `0x2c7ce50..0x2c7ce69` | 25 | 21/25 | 1 | serde Visitor::expecting (struct Hip3DeployerFeeState) (0x2c7ce50) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `dex-registry` | `0x44dc550..0x44dc569` | 25 | 21/25 | 1 | serde Visitor::expecting (struct Hip3DeployerFeeState) (0x44dc550) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `dex-registry` | `0x5616bd0..0x5616be9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct Hip3DeployerFeeState) (0x5616bd0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `dex-registry` | `0x2c7cff0..0x2c7d009` | 25 | 21/25 | 1 | serde Visitor::expecting (struct Hip3Limits) (0x2c7cff0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `dex-registry` | `0x44dc2f0..0x44dc309` | 25 | 21/25 | 1 | serde Visitor::expecting (struct Hip3Limits) (0x44dc2f0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `dex-registry` | `0x5616b10..0x5616b29` | 25 | 21/25 | 1 | serde Visitor::expecting (struct Hip3Limits) (0x5616b10) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `dex-registry` | `0x292ced0..0x292cee9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct Hip3SchemaInput) (0x292ced0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `dex-registry` | `0x36647f0..0x3664809` | 25 | 21/25 | 1 | serde Visitor::expecting (struct Hip3SchemaInput) (0x36647f0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `dex-registry` | `0x51adb70..0x51adb89` | 25 | 21/25 | 1 | serde Visitor::expecting (struct Hip3SchemaInput) (0x51adb70) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `dex-registry` | `0x2c7d030..0x2c7d049` | 25 | 21/25 | 1 | serde Visitor::expecting (struct Hip3State) (0x2c7d030) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `dex-registry` | `0x44dc230..0x44dc249` | 25 | 21/25 | 1 | serde Visitor::expecting (struct Hip3State) (0x44dc230) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `dex-registry` | `0x5616710..0x5616729` | 25 | 21/25 | 1 | serde Visitor::expecting (struct Hip3State) (0x5616710) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `evm` | `0x29b0470..0x29b0489` | 25 | 21/25 | 1 | serde Visitor::expecting (struct HyperEvm) (0x29b0470) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `evm` | `0x4351180..0x4351199` | 25 | 21/25 | 1 | serde Visitor::expecting (struct HyperEvm) (0x4351180) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `evm` | `0x5616690..0x56166a9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct HyperEvm) (0x5616690) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `l1-shared` | `0x2d4a550..0x2d4a569` | 25 | 21/25 | 1 | serde Visitor::expecting (struct Hyperliquidity) (0x2d4a550) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `l1-shared` | `0x38db740..0x38db759` | 25 | 21/25 | 1 | serde Visitor::expecting (struct Hyperliquidity) (0x38db740) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `l1-shared` | `0x51add50..0x51add69` | 25 | 21/25 | 1 | serde Visitor::expecting (struct Hyperliquidity) (0x51add50) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `storage` | `0x1500a40..0x1500a59` | 25 | 21/25 | 1 | serde Visitor::expecting (struct IndexedArtifactSerde) (0x1500a40) | `research/work-items/RE-009-node115-storage-abci-byte-matches/README.md` |
| `storage` | `0x57d19b0..0x57d19c9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct IndexedArtifactSerde) (0x57d19b0) | `research/work-items/RE-009-node115-storage-abci-byte-matches/README.md` |
| `evm-rpc` | `0x174c710..0x174c729` | 25 | 21/25 | 1 | serde Visitor::expecting (struct JsonRpcError) (0x174c710) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `evm-rpc` | `0x174c770..0x174c789` | 25 | 21/25 | 1 | serde Visitor::expecting (struct JsonRpcResponse) (0x174c770) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `evm` | `0x22f5a00..0x22f5a19` | 25 | 21/25 | 1 | serde Visitor::expecting (struct L1ToEvmErc20Transfer) (0x22f5a00) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `evm` | `0x38db8c0..0x38db8d9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct L1ToEvmErc20Transfer) (0x38db8c0) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `evm` | `0x5b092f0..0x5b09309` | 25 | 21/25 | 1 | serde Visitor::expecting (struct L1ToEvmErc20Transfer) (0x5b092f0) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `evm` | `0x22f5740..0x22f5759` | 25 | 21/25 | 1 | serde Visitor::expecting (struct L1ToEvmNativeTokenTransfer) (0x22f5740) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `evm` | `0x38dbd60..0x38dbd79` | 25 | 21/25 | 1 | serde Visitor::expecting (struct L1ToEvmNativeTokenTransfer) (0x38dbd60) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `evm` | `0x5b09510..0x5b09529` | 25 | 21/25 | 1 | serde Visitor::expecting (struct L1ToEvmNativeTokenTransfer) (0x5b09510) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `orderbook` | `0x2420630..0x2420649` | 25 | 21/25 | 1 | serde Visitor::expecting (struct Level) (0x2420630) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x44dc390..0x44dc3a9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct Level) (0x44dc390) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x51ad980..0x51ad999` | 25 | 21/25 | 1 | serde Visitor::expecting (struct Level) (0x51ad980) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x2420780..0x2420799` | 25 | 21/25 | 1 | serde Visitor::expecting (struct LevelSummary) (0x2420780) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x44dc810..0x44dc829` | 25 | 21/25 | 1 | serde Visitor::expecting (struct LevelSummary) (0x44dc810) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x51ad310..0x51ad329` | 25 | 21/25 | 1 | serde Visitor::expecting (struct LevelSummary) (0x51ad310) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `risk` | `0x2420040..0x2420059` | 25 | 21/25 | 1 | serde Visitor::expecting (struct LiquidationCounters) (0x2420040) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `risk` | `0x3c4d110..0x3c4d129` | 25 | 21/25 | 1 | serde Visitor::expecting (struct LiquidationCounters) (0x3c4d110) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `risk` | `0x4d9bf00..0x4d9bf19` | 25 | 21/25 | 1 | serde Visitor::expecting (struct LiquidationCounters) (0x4d9bf00) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `serialization` | `0x29b0550..0x29b0569` | 25 | 21/25 | 1 | serde Visitor::expecting (struct LogFlattenDeserializer) (0x29b0550) | `research/work-items/RE-012-node115-artifact-and-stream-msg/README.md` |
| `serialization` | `0x50d9500..0x50d9519` | 25 | 21/25 | 1 | serde Visitor::expecting (struct LogFlattenDeserializer) (0x50d9500) | `research/work-items/RE-012-node115-artifact-and-stream-msg/README.md` |
| `serialization` | `0x29b05d0..0x29b05e9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct LogUnflattenDeserializer) (0x29b05d0) | `research/work-items/RE-012-node115-artifact-and-stream-msg/README.md` |
| `serialization` | `0x50d93a0..0x50d93b9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct LogUnflattenDeserializer) (0x50d93a0) | `research/work-items/RE-012-node115-artifact-and-stream-msg/README.md` |
| `abci` | `0x36cd190..0x36cd1a9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct LtHash) (0x36cd190) | `research/work-items/RE-009-node115-storage-abci-byte-matches/README.md` |
| `abci` | `0x38dbb80..0x38dbb99` | 25 | 21/25 | 1 | serde Visitor::expecting (struct LtHashes) (0x38dbb80) | `research/work-items/RE-009-node115-storage-abci-byte-matches/README.md` |
| `fees` | `0x2773630..0x2773649` | 25 | 21/25 | 1 | serde Visitor::expecting (struct MmFees) (0x2773630) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `fees` | `0x36cd4d0..0x36cd4e9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct MmFees) (0x36cd4d0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `fees` | `0x5616c90..0x5616ca9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct MmFees) (0x5616c90) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `action-wire` | `0x292d3d0..0x292d3e9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct ModifyAction) (0x292d3d0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `action-wire` | `0x3bd13c0..0x3bd13d9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct ModifyAction) (0x3bd13c0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `action-wire` | `0x51add10..0x51add29` | 25 | 21/25 | 1 | serde Visitor::expecting (struct ModifyAction) (0x51add10) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `orderbook` | `0x292cf10..0x292cf29` | 25 | 21/25 | 1 | serde Visitor::expecting (struct ModifyWire) (0x292cf10) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x3bcda80..0x3bcda99` | 25 | 21/25 | 1 | serde Visitor::expecting (struct ModifyWire) (0x3bcda80) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x51add70..0x51add89` | 25 | 21/25 | 1 | serde Visitor::expecting (struct ModifyWire) (0x51add70) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `vaults` | `0x2773650..0x2773669` | 25 | 21/25 | 1 | serde Visitor::expecting (struct NetChildVaultPositionsAction) (0x2773650) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `vaults` | `0x46976f0..0x4697709` | 25 | 21/25 | 1 | serde Visitor::expecting (struct NetChildVaultPositionsAction) (0x46976f0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `vaults` | `0x53d6930..0x53d6949` | 25 | 21/25 | 1 | serde Visitor::expecting (struct NetChildVaultPositionsAction) (0x53d6930) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `fees` | `0x2773890..0x27738a9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct NewFeeSchedule) (0x2773890) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `fees` | `0x5616550..0x5616569` | 25 | 21/25 | 1 | serde Visitor::expecting (struct NewFeeSchedule) (0x5616550) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `storage` | `0x15a0290..0x15a02a9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct NodeArtifact) (0x15a0290) | `research/work-items/RE-009-node115-storage-abci-byte-matches/README.md` |
| `storage` | `0x5616b50..0x5616b69` | 25 | 21/25 | 1 | serde Visitor::expecting (struct NodeArtifact) (0x5616b50) | `research/work-items/RE-009-node115-storage-abci-byte-matches/README.md` |
| `transport` | `0x2a8e070..0x2a8e089` | 25 | 21/25 | 1 | serde Visitor::expecting (struct NodeGossipPriorityConfig) (0x2a8e070) | `research/work-items/RE-012-node115-gossip-rpc-connections-local-state/README.md` |
| `transport` | `0x5a2f3f0..0x5a2f409` | 25 | 21/25 | 1 | serde Visitor::expecting (struct NodeGossipPriorityConfig) (0x5a2f3f0) | `research/work-items/RE-012-node115-gossip-rpc-connections-local-state/README.md` |
| `node-runtime` | `0x15b8b30..0x15b8b49` | 25 | 21/25 | 1 | serde Visitor::expecting (struct NodeMetadata) (0x15b8b30) | `research/work-items/RE-012-node115-artifact-and-stream-msg/README.md` |
| `node-runtime` | `0x5a2f3b0..0x5a2f3c9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct NodeMetadata) (0x5a2f3b0) | `research/work-items/RE-012-node115-artifact-and-stream-msg/README.md` |
| `orderbook` | `0x2d4a7d0..0x2d4a7e9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct OpenOrderTracker) (0x2d4a7d0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x44dca50..0x44dca69` | 25 | 21/25 | 1 | serde Visitor::expecting (struct OpenOrderTracker) (0x44dca50) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x51adbb0..0x51adbc9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct OpenOrderTracker) (0x51adbb0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `action-wire` | `0x2d4a630..0x2d4a649` | 25 | 21/25 | 1 | serde Visitor::expecting (struct OrderAction) (0x2d4a630) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `action-wire` | `0x3659730..0x3659749` | 25 | 21/25 | 1 | serde Visitor::expecting (struct OrderAction) (0x3659730) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `action-wire` | `0x5941e10..0x5941e29` | 25 | 21/25 | 1 | serde Visitor::expecting (struct OrderAction) (0x5941e10) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `orderbook` | `0x2d4a710..0x2d4a729` | 25 | 21/25 | 1 | serde Visitor::expecting (struct OrderBuilderInfo) (0x2d4a710) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x36cd090..0x36cd0a9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct OrderBuilderInfo) (0x36cd090) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x5942050..0x5942069` | 25 | 21/25 | 1 | serde Visitor::expecting (struct OrderBuilderInfo) (0x5942050) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x25eb740..0x25eb759` | 25 | 21/25 | 1 | serde Visitor::expecting (struct OrderCore) (0x25eb740) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x44dc170..0x44dc189` | 25 | 21/25 | 1 | serde Visitor::expecting (struct OrderCore) (0x44dc170) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x51ad760..0x51ad779` | 25 | 21/25 | 1 | serde Visitor::expecting (struct OrderCore) (0x51ad760) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x292d4f0..0x292d509` | 25 | 21/25 | 1 | serde Visitor::expecting (struct OrderWireSerde) (0x292d4f0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x3bcfad0..0x3bcfae9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct OrderWireSerde) (0x3bcfad0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x51ad9c0..0x51ad9d9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct OrderWireSerde) (0x51ad9c0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `evm-rpc` | `0x174c790..0x174c7a9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct ParamsObject) (0x174c790) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `evm-rpc` | `0x29b02f0..0x29b0309` | 25 | 21/25 | 1 | serde Visitor::expecting (struct ParamsObject) (0x29b02f0) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `vaults` | `0x2773850..0x2773869` | 25 | 21/25 | 1 | serde Visitor::expecting (struct ParentVaultState) (0x2773850) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `vaults` | `0x36cced0..0x36ccee9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct ParentVaultState) (0x36cced0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `vaults` | `0x5b08f90..0x5b08fa9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct ParentVaultState) (0x5b08f90) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `bridge` | `0x2773350..0x2773369` | 25 | 21/25 | 1 | serde Visitor::expecting (struct PendingWithdrawals) (0x2773350) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `bridge` | `0x36cd230..0x36cd249` | 25 | 21/25 | 1 | serde Visitor::expecting (struct PendingWithdrawals) (0x36cd230) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `bridge` | `0x59425b0..0x59425c9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct PendingWithdrawals) (0x59425b0) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `assets` | `0x2d4a510..0x2d4a529` | 25 | 21/25 | 1 | serde Visitor::expecting (struct PerpAssetInfo) (0x2d4a510) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `assets` | `0x44dc350..0x44dc369` | 25 | 21/25 | 1 | serde Visitor::expecting (struct PerpAssetInfo) (0x44dc350) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `assets` | `0x53d65d0..0x53d65e9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct PerpAssetInfo) (0x53d65d0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `dex-registry` | `0x292d7d0..0x292d7e9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct PerpDex) (0x292d7d0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `dex-registry` | `0x4228f70..0x4228f89` | 25 | 21/25 | 1 | serde Visitor::expecting (struct PerpDex) (0x4228f70) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `dex-registry` | `0x53d57f0..0x53d5809` | 25 | 21/25 | 1 | serde Visitor::expecting (struct PerpDex) (0x53d57f0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `assets` | `0x292cad0..0x292cae9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct PerpMeta) (0x292cad0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `assets` | `0x3c4d890..0x3c4d8a9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct PerpMeta) (0x3c4d890) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `assets` | `0x5a2f0f0..0x5a2f109` | 25 | 21/25 | 1 | serde Visitor::expecting (struct PerpMeta) (0x5a2f0f0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `risk` | `0x2420180..0x2420199` | 25 | 21/25 | 1 | serde Visitor::expecting (struct PositionMap) (0x2420180) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `risk` | `0x42298f0..0x4229909` | 25 | 21/25 | 1 | serde Visitor::expecting (struct PositionMap) (0x42298f0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `risk` | `0x51ad6e0..0x51ad6f9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct PositionMap) (0x51ad6e0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `evm` | `0x26a17c0..0x26a17d9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct ReadPrecompileInput) (0x26a17c0) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `evm` | `0x5b08ed0..0x5b08ee9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct ReadPrecompileInput) (0x5b08ed0) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `evm` | `0x22f56e0..0x22f56f9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct ReceiptWire) (0x22f56e0) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `evm` | `0x5b09610..0x5b09629` | 25 | 21/25 | 1 | serde Visitor::expecting (struct ReceiptWire) (0x5b09610) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `fees` | `0x27736b0..0x27736c9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct ReferralState) (0x27736b0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `fees` | `0x3c4d750..0x3c4d769` | 25 | 21/25 | 1 | serde Visitor::expecting (struct ReferralState) (0x3c4d750) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `fees` | `0x51ad640..0x51ad659` | 25 | 21/25 | 1 | serde Visitor::expecting (struct ReferralState) (0x51ad640) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `fees` | `0x2773ab0..0x2773ac9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct ReferrerState) (0x2773ab0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `fees` | `0x3c4d450..0x3c4d469` | 25 | 21/25 | 1 | serde Visitor::expecting (struct ReferrerState) (0x3c4d450) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `fees` | `0x51adad0..0x51adae9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct ReferrerState) (0x51adad0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `vaults` | `0x25eb8a0..0x25eb8b9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct Relationships) (0x25eb8a0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `vaults` | `0x44dca90..0x44dcaa9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct Relationships) (0x44dca90) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `vaults` | `0x51adb90..0x51adba9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct Relationships) (0x51adb90) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `action-wire` | `0x292c8d0..0x292c8e9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct ReserveRequestWeightAction) (0x292c8d0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `action-wire` | `0x3bddbc0..0x3bddbd9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct ReserveRequestWeightAction) (0x3bddbc0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `action-wire` | `0x59426d0..0x59426e9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct ReserveRequestWeightAction) (0x59426d0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `fees` | `0x2773150..0x2773169` | 25 | 21/25 | 1 | serde Visitor::expecting (struct ScaledAndRawVlm) (0x2773150) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `fees` | `0x36cd010..0x36cd029` | 25 | 21/25 | 1 | serde Visitor::expecting (struct ScaledAndRawVlm) (0x36cd010) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `fees` | `0x4d9c980..0x4d9c999` | 25 | 21/25 | 1 | serde Visitor::expecting (struct ScaledAndRawVlm) (0x4d9c980) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `action-wire` | `0x292d1d0..0x292d1e9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct ScheduleCancelAction) (0x292d1d0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `action-wire` | `0x4458150..0x4458169` | 25 | 21/25 | 1 | serde Visitor::expecting (struct ScheduleCancelAction) (0x4458150) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `action-wire` | `0x53d5bd0..0x53d5be9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct ScheduleCancelAction) (0x53d5bd0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `orderbook` | `0x24208e0..0x24208f9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct ScheduledCancel) (0x24208e0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x3c4d8b0..0x3c4d8c9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct ScheduledCancel) (0x3c4d8b0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x4d9c350..0x4d9c369` | 25 | 21/25 | 1 | serde Visitor::expecting (struct ScheduledCancel) (0x4d9c350) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `evm` | `0x22f58e0..0x22f58f9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct SealedBlockWire) (0x22f58e0) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `evm` | `0x44dc770..0x44dc789` | 25 | 21/25 | 1 | serde Visitor::expecting (struct SealedBlockWire) (0x44dc770) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `evm` | `0x5b09470..0x5b09489` | 25 | 21/25 | 1 | serde Visitor::expecting (struct SealedBlockWire) (0x5b09470) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `action-wire` | `0x2420b00..0x2420b19` | 25 | 21/25 | 1 | serde Visitor::expecting (struct SendAssetAction) (0x2420b00) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `action-wire` | `0x4452950..0x4452969` | 25 | 21/25 | 1 | serde Visitor::expecting (struct SendAssetAction) (0x4452950) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `action-wire` | `0x59420f0..0x5942109` | 25 | 21/25 | 1 | serde Visitor::expecting (struct SendAssetAction) (0x59420f0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `evm` | `0x22f5ac0..0x22f5ad9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct SendToEvmData) (0x22f5ac0) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `evm` | `0x44dccb0..0x44dccc9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct SendToEvmData) (0x44dccb0) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `evm` | `0x5b09690..0x5b096a9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct SendToEvmData) (0x5b09690) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `evm` | `0x24207c0..0x24207d9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct SendToEvmWithDataAction) (0x24207c0) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `evm` | `0x4461370..0x4461389` | 25 | 21/25 | 1 | serde Visitor::expecting (struct SendToEvmWithDataAction) (0x4461370) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `evm` | `0x59421d0..0x59421e9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct SendToEvmWithDataAction) (0x59421d0) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `action-wire` | `0x2420720..0x2420739` | 25 | 21/25 | 1 | serde Visitor::expecting (struct SetDisplayNameAction) (0x2420720) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `action-wire` | `0x4692c40..0x4692c59` | 25 | 21/25 | 1 | serde Visitor::expecting (struct SetDisplayNameAction) (0x4692c40) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `action-wire` | `0x53d6570..0x53d6589` | 25 | 21/25 | 1 | serde Visitor::expecting (struct SetDisplayNameAction) (0x53d6570) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `action-wire` | `0x24208a0..0x24208b9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct SetReferrerAction) (0x24208a0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `action-wire` | `0x4454bc0..0x4454bd9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct SetReferrerAction) (0x4454bc0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `action-wire` | `0x53d5a30..0x53d5a49` | 25 | 21/25 | 1 | serde Visitor::expecting (struct SetReferrerAction) (0x53d5a30) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `orderbook` | `0x2420900..0x2420919` | 25 | 21/25 | 1 | serde Visitor::expecting (struct Slab) (0x2420900) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x42296b0..0x42296c9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct Slab) (0x42296b0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x5941ed0..0x5941ee9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct Slab) (0x5941ed0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `risk` | `0x22f5ba0..0x22f5bb9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct SpotClearinghouse) (0x22f5ba0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `risk` | `0x3c4d2f0..0x3c4d309` | 25 | 21/25 | 1 | serde Visitor::expecting (struct SpotClearinghouse) (0x3c4d2f0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `risk` | `0x5b096b0..0x5b096c9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct SpotClearinghouse) (0x5b096b0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `assets` | `0x292dbf0..0x292dc09` | 25 | 21/25 | 1 | serde Visitor::expecting (struct SpotInfo) (0x292dbf0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `assets` | `0x3c4d8f0..0x3c4d909` | 25 | 21/25 | 1 | serde Visitor::expecting (struct SpotInfo) (0x3c4d8f0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `assets` | `0x5a2eef0..0x5a2ef09` | 25 | 21/25 | 1 | serde Visitor::expecting (struct SpotInfo) (0x5a2eef0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `assets` | `0x292d350..0x292d369` | 25 | 21/25 | 1 | serde Visitor::expecting (struct SpotMeta) (0x292d350) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `assets` | `0x3c4d0d0..0x3c4d0e9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct SpotMeta) (0x3c4d0d0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `assets` | `0x5a2f150..0x5a2f169` | 25 | 21/25 | 1 | serde Visitor::expecting (struct SpotMeta) (0x5a2f150) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `action-wire` | `0x2420760..0x2420779` | 25 | 21/25 | 1 | serde Visitor::expecting (struct SpotSendAction) (0x2420760) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `action-wire` | `0x4451b10..0x4451b29` | 25 | 21/25 | 1 | serde Visitor::expecting (struct SpotSendAction) (0x4451b10) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `action-wire` | `0x5942690..0x59426a9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct SpotSendAction) (0x5942690) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `fees` | `0x2773430..0x2773449` | 25 | 21/25 | 1 | serde Visitor::expecting (struct StakeDiscount) (0x2773430) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `fees` | `0x36cd0f0..0x36cd109` | 25 | 21/25 | 1 | serde Visitor::expecting (struct StakeDiscount) (0x36cd0f0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `fees` | `0x5616a30..0x5616a49` | 25 | 21/25 | 1 | serde Visitor::expecting (struct StakeDiscount) (0x5616a30) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `fees` | `0x2773550..0x2773569` | 25 | 21/25 | 1 | serde Visitor::expecting (struct StakeDiscountTiers) (0x2773550) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `fees` | `0x36cd070..0x36cd089` | 25 | 21/25 | 1 | serde Visitor::expecting (struct StakeDiscountTiers) (0x36cd070) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `fees` | `0x5616570..0x5616589` | 25 | 21/25 | 1 | serde Visitor::expecting (struct StakeDiscountTiers) (0x5616570) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `constants` | `0x17785d0..0x17785e9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct StaticConfig) (0x17785d0) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `vaults` | `0x2773af0..0x2773b09` | 25 | 21/25 | 1 | serde Visitor::expecting (struct SubAccount) (0x2773af0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `vaults` | `0x36cd310..0x36cd329` | 25 | 21/25 | 1 | serde Visitor::expecting (struct SubAccount) (0x36cd310) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `vaults` | `0x4d9bf60..0x4d9bf79` | 25 | 21/25 | 1 | serde Visitor::expecting (struct SubAccount) (0x4d9bf60) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `vaults` | `0x292ca30..0x292ca49` | 25 | 21/25 | 1 | serde Visitor::expecting (struct SubAccountSpotTransferAction) (0x292ca30) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `vaults` | `0x4697710..0x4697729` | 25 | 21/25 | 1 | serde Visitor::expecting (struct SubAccountSpotTransferAction) (0x4697710) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `vaults` | `0x53d5e30..0x53d5e49` | 25 | 21/25 | 1 | serde Visitor::expecting (struct SubAccountSpotTransferAction) (0x53d5e30) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `vaults` | `0x2773170..0x2773189` | 25 | 21/25 | 1 | serde Visitor::expecting (struct SubAccountTracker) (0x2773170) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `vaults` | `0x36ccf50..0x36ccf69` | 25 | 21/25 | 1 | serde Visitor::expecting (struct SubAccountTracker) (0x36ccf50) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `vaults` | `0x4d9c590..0x4d9c5a9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct SubAccountTracker) (0x4d9c590) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `vaults` | `0x24209e0..0x24209f9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct SubAccountTransferAction) (0x24209e0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `vaults` | `0x4695d40..0x4695d59` | 25 | 21/25 | 1 | serde Visitor::expecting (struct SubAccountTransferAction) (0x4695d40) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `vaults` | `0x53d59b0..0x53d59c9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct SubAccountTransferAction) (0x53d59b0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `assets` | `0x292ceb0..0x292cec9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct TokenInfo) (0x292ceb0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `assets` | `0x3c4d790..0x3c4d7a9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct TokenInfo) (0x3c4d790) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `assets` | `0x5a2f330..0x5a2f349` | 25 | 21/25 | 1 | serde Visitor::expecting (struct TokenInfo) (0x5a2f330) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `assets` | `0x292ce70..0x292ce89` | 25 | 21/25 | 1 | serde Visitor::expecting (struct TokenSpec) (0x292ce70) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `assets` | `0x3c4d050..0x3c4d069` | 25 | 21/25 | 1 | serde Visitor::expecting (struct TokenSpec) (0x3c4d050) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `assets` | `0x5a2efb0..0x5a2efc9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct TokenSpec) (0x5a2efb0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `bridge` | `0x2773ad0..0x2773ae9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct TotalWithdrawal) (0x2773ad0) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `bridge` | `0x36cd0b0..0x36cd0c9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct TotalWithdrawal) (0x36cd0b0) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `bridge` | `0x5941db0..0x5941dc9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct TotalWithdrawal) (0x5941db0) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `orderbook` | `0x2d4a3a0..0x2d4a3b9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct TrailingStopOrder) (0x2d4a3a0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x38db840..0x38db859` | 25 | 21/25 | 1 | serde Visitor::expecting (struct TrailingStopOrder) (0x38db840) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x5a2f010..0x5a2f029` | 25 | 21/25 | 1 | serde Visitor::expecting (struct TrailingStopOrder) (0x5a2f010) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `serialization` | `0x22f5be0..0x22f5bf9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct TransactionSignedWire) (0x22f5be0) | `research/work-items/RE-012-node115-artifact-and-stream-msg/README.md` |
| `serialization` | `0x44dc510..0x44dc529` | 25 | 21/25 | 1 | serde Visitor::expecting (struct TransactionSignedWire) (0x44dc510) | `research/work-items/RE-012-node115-artifact-and-stream-msg/README.md` |
| `serialization` | `0x5b09670..0x5b09689` | 25 | 21/25 | 1 | serde Visitor::expecting (struct TransactionSignedWire) (0x5b09670) | `research/work-items/RE-012-node115-artifact-and-stream-msg/README.md` |
| `orderbook` | `0x2420220..0x2420239` | 25 | 21/25 | 1 | serde Visitor::expecting (struct Trigger) (0x2420220) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x44dc1d0..0x44dc1e9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct Trigger) (0x44dc1d0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x5a2ef90..0x5a2efa9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct Trigger) (0x5a2ef90) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x2420470..0x2420489` | 25 | 21/25 | 1 | serde Visitor::expecting (struct TriggerOrder) (0x2420470) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x44dc530..0x44dc549` | 25 | 21/25 | 1 | serde Visitor::expecting (struct TriggerOrder) (0x44dc530) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x5a2f4b0..0x5a2f4c9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct TriggerOrder) (0x5a2f4b0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x2773670..0x2773689` | 25 | 21/25 | 1 | serde Visitor::expecting (struct TriggerWireSerde) (0x2773670) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x41fe370..0x41fe389` | 25 | 21/25 | 1 | serde Visitor::expecting (struct TriggerWireSerde) (0x41fe370) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x51add30..0x51add49` | 25 | 21/25 | 1 | serde Visitor::expecting (struct TriggerWireSerde) (0x51add30) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `action-wire` | `0x29b0450..0x29b0469` | 25 | 21/25 | 1 | serde Visitor::expecting (struct TwapCancelAction) (0x29b0450) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `action-wire` | `0x4684830..0x4684849` | 25 | 21/25 | 1 | serde Visitor::expecting (struct TwapCancelAction) (0x4684830) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `action-wire` | `0x53d5c70..0x53d5c89` | 25 | 21/25 | 1 | serde Visitor::expecting (struct TwapCancelAction) (0x53d5c70) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `orderbook` | `0x292ccb0..0x292ccc9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct TwapDetailsWire) (0x292ccb0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x3bcfa70..0x3bcfa89` | 25 | 21/25 | 1 | serde Visitor::expecting (struct TwapDetailsWire) (0x3bcfa70) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x51adc50..0x51adc69` | 25 | 21/25 | 1 | serde Visitor::expecting (struct TwapDetailsWire) (0x51adc50) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x2d4a5f0..0x2d4a609` | 25 | 21/25 | 1 | serde Visitor::expecting (struct TwapHeapKey) (0x2d4a5f0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x38db8e0..0x38db8f9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct TwapHeapKey) (0x38db8e0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x5a2f3d0..0x5a2f3e9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct TwapHeapKey) (0x5a2f3d0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `action-wire` | `0x292d230..0x292d249` | 25 | 21/25 | 1 | serde Visitor::expecting (struct TwapOrderAction) (0x292d230) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `action-wire` | `0x3bd3880..0x3bd3899` | 25 | 21/25 | 1 | serde Visitor::expecting (struct TwapOrderAction) (0x3bd3880) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `action-wire` | `0x53d6470..0x53d6489` | 25 | 21/25 | 1 | serde Visitor::expecting (struct TwapOrderAction) (0x53d6470) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `orderbook` | `0x2d4a5d0..0x2d4a5e9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct TwapSchedule) (0x2d4a5d0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x38db9c0..0x38db9d9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct TwapSchedule) (0x38db9c0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x5a2f170..0x5a2f189` | 25 | 21/25 | 1 | serde Visitor::expecting (struct TwapSchedule) (0x5a2f170) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x2d4a2a0..0x2d4a2b9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct TwapState) (0x2d4a2a0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x38dbba0..0x38dbbb9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct TwapState) (0x38dbba0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x5a2efd0..0x5a2efe9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct TwapState) (0x5a2efd0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x2d4a300..0x2d4a319` | 25 | 21/25 | 1 | serde Visitor::expecting (struct TwapTracker) (0x2d4a300) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x38db640..0x38db659` | 25 | 21/25 | 1 | serde Visitor::expecting (struct TwapTracker) (0x38db640) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x5a2f270..0x5a2f289` | 25 | 21/25 | 1 | serde Visitor::expecting (struct TwapTracker) (0x5a2f270) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x2d4a3e0..0x2d4a3f9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct TwapTrigger) (0x2d4a3e0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x38db920..0x38db939` | 25 | 21/25 | 1 | serde Visitor::expecting (struct TwapTrigger) (0x38db920) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x5a2f070..0x5a2f089` | 25 | 21/25 | 1 | serde Visitor::expecting (struct TwapTrigger) (0x5a2f070) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x292c9f0..0x292ca09` | 25 | 21/25 | 1 | serde Visitor::expecting (struct TwapTriggerWire) (0x292c9f0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x3bcfa90..0x3bcfaa9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct TwapTriggerWire) (0x3bcfa90) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x51ad960..0x51ad979` | 25 | 21/25 | 1 | serde Visitor::expecting (struct TwapTriggerWire) (0x51ad960) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x292d450..0x292d469` | 25 | 21/25 | 1 | serde Visitor::expecting (struct TwapWireSerde) (0x292d450) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x3bce9e0..0x3bce9f9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct TwapWireSerde) (0x3bce9e0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x51ada00..0x51ada19` | 25 | 21/25 | 1 | serde Visitor::expecting (struct TwapWireSerde) (0x51ada00) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `evm` | `0x22f59a0..0x22f59b9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct TxEip1559Wire) (0x22f59a0) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `evm` | `0x44dc9d0..0x44dc9e9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct TxEip1559Wire) (0x44dc9d0) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `evm` | `0x5b09430..0x5b09449` | 25 | 21/25 | 1 | serde Visitor::expecting (struct TxEip1559Wire) (0x5b09430) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `evm` | `0x22f58a0..0x22f58b9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct TxEip2930Wire) (0x22f58a0) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `evm` | `0x44dc410..0x44dc429` | 25 | 21/25 | 1 | serde Visitor::expecting (struct TxEip2930Wire) (0x44dc410) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `evm` | `0x5b09870..0x5b09889` | 25 | 21/25 | 1 | serde Visitor::expecting (struct TxEip2930Wire) (0x5b09870) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `evm` | `0x22f5c00..0x22f5c19` | 25 | 21/25 | 1 | serde Visitor::expecting (struct TxEip4844Wire) (0x22f5c00) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `evm` | `0x44dc4b0..0x44dc4c9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct TxEip4844Wire) (0x44dc4b0) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `evm` | `0x5b09410..0x5b09429` | 25 | 21/25 | 1 | serde Visitor::expecting (struct TxEip4844Wire) (0x5b09410) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `evm` | `0x22f57c0..0x22f57d9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct TxEip7702Wire) (0x22f57c0) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `evm` | `0x44dc5d0..0x44dc5e9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct TxEip7702Wire) (0x44dc5d0) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `evm` | `0x5b09550..0x5b09569` | 25 | 21/25 | 1 | serde Visitor::expecting (struct TxEip7702Wire) (0x5b09550) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `evm` | `0x22f5960..0x22f5979` | 25 | 21/25 | 1 | serde Visitor::expecting (struct TxLegacyWire) (0x22f5960) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `evm` | `0x44dc370..0x44dc389` | 25 | 21/25 | 1 | serde Visitor::expecting (struct TxLegacyWire) (0x44dc370) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `evm` | `0x5b09790..0x5b097a9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct TxLegacyWire) (0x5b09790) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `fees` | `0x292da50..0x292da69` | 25 | 21/25 | 1 | serde Visitor::expecting (struct UnvalidatedHip3DeployerFee) (0x292da50) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `fees` | `0x3668210..0x3668229` | 25 | 21/25 | 1 | serde Visitor::expecting (struct UnvalidatedHip3DeployerFee) (0x3668210) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `fees` | `0x51ad6c0..0x51ad6d9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct UnvalidatedHip3DeployerFee) (0x51ad6c0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `action-wire` | `0x25ebaf0..0x25ebb09` | 25 | 21/25 | 1 | serde Visitor::expecting (struct UpdateIsolatedMarginAction) (0x25ebaf0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `action-wire` | `0x3bddbe0..0x3bddbf9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct UpdateIsolatedMarginAction) (0x3bddbe0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `action-wire` | `0x51adcd0..0x51adce9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct UpdateIsolatedMarginAction) (0x51adcd0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `action-wire` | `0x2420a00..0x2420a19` | 25 | 21/25 | 1 | serde Visitor::expecting (struct UsdClassTransferAction) (0x2420a00) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `action-wire` | `0x445cea0..0x445ceb9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct UsdClassTransferAction) (0x445cea0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `action-wire` | `0x5941f90..0x5941fa9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct UsdClassTransferAction) (0x5941f90) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `action-wire` | `0x24200e0..0x24200f9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct UsdSendAction) (0x24200e0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `action-wire` | `0x4450d60..0x4450d79` | 25 | 21/25 | 1 | serde Visitor::expecting (struct UsdSendAction) (0x4450d60) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `action-wire` | `0x5942310..0x5942329` | 25 | 21/25 | 1 | serde Visitor::expecting (struct UsdSendAction) (0x5942310) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `orderbook` | `0x2773e30..0x2773e49` | 25 | 21/25 | 1 | serde Visitor::expecting (struct UserCloidTracker) (0x2773e30) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x4351280..0x4351299` | 25 | 21/25 | 1 | serde Visitor::expecting (struct UserCloidTracker) (0x4351280) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x4d9bf40..0x4d9bf59` | 25 | 21/25 | 1 | serde Visitor::expecting (struct UserCloidTracker) (0x4d9bf40) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `fees` | `0x292cd90..0x292cda9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct UserFeeState) (0x292cd90) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `fees` | `0x3c4d370..0x3c4d389` | 25 | 21/25 | 1 | serde Visitor::expecting (struct UserFeeState) (0x3c4d370) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `fees` | `0x5616630..0x5616649` | 25 | 21/25 | 1 | serde Visitor::expecting (struct UserFeeState) (0x5616630) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `action-wire` | `0x2420020..0x2420039` | 25 | 21/25 | 1 | serde Visitor::expecting (struct UserSetAbstractionAction) (0x2420020) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `action-wire` | `0x4461350..0x4461369` | 25 | 21/25 | 1 | serde Visitor::expecting (struct UserSetAbstractionAction) (0x4461350) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `action-wire` | `0x53d6a90..0x53d6aa9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct UserSetAbstractionAction) (0x53d6a90) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `risk` | `0x2420ac0..0x2420ad9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct UserState) (0x2420ac0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `risk` | `0x2773ed0..0x2773ee9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct UserState) (0x2773ed0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `risk` | `0x292cd10..0x292cd29` | 25 | 21/25 | 1 | serde Visitor::expecting (struct UserState) (0x292cd10) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `risk` | `0x292d390..0x292d3a9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct UserState) (0x292d390) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `risk` | `0x2c7cd20..0x2c7cd39` | 25 | 21/25 | 1 | serde Visitor::expecting (struct UserState) (0x2c7cd20) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `risk` | `0x2c7d0d0..0x2c7d0e9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct UserState) (0x2c7d0d0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `risk` | `0x36cd4b0..0x36cd4c9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct UserState) (0x36cd4b0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `risk` | `0x3c4d170..0x3c4d189` | 25 | 21/25 | 1 | serde Visitor::expecting (struct UserState) (0x3c4d170) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `risk` | `0x42294e0..0x42294f9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct UserState) (0x42294e0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `risk` | `0x44dc950..0x44dc969` | 25 | 21/25 | 1 | serde Visitor::expecting (struct UserState) (0x44dc950) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `risk` | `0x4d9bec0..0x4d9bed9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct UserState) (0x4d9bec0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `risk` | `0x4d9c610..0x4d9c629` | 25 | 21/25 | 1 | serde Visitor::expecting (struct UserState) (0x4d9c610) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `risk` | `0x56167f0..0x5616809` | 25 | 22/25 | 1 | serde Visitor::expecting (struct UserState) (0x56167f0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `risk` | `0x56168d0..0x56168e9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct UserState) (0x56168d0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `risk` | `0x5616990..0x56169a9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct UserState) (0x5616990) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `risk` | `0x2420530..0x2420549` | 25 | 21/25 | 1 | serde Visitor::expecting (struct UserStateSerde) (0x2420530) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `risk` | `0x38db6e0..0x38db6f9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct UserStateSerde) (0x38db6e0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `risk` | `0x5942010..0x5942029` | 25 | 21/25 | 1 | serde Visitor::expecting (struct UserStateSerde) (0x5942010) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `node-runtime` | `0x292cb50..0x292cb69` | 25 | 21/25 | 1 | serde Visitor::expecting (struct ValidatorL1StreamAction) (0x292cb50) | `research/work-items/RE-012-node115-artifact-and-stream-msg/README.md` |
| `node-runtime` | `0x366a020..0x366a039` | 25 | 21/25 | 1 | serde Visitor::expecting (struct ValidatorL1StreamAction) (0x366a020) | `research/work-items/RE-012-node115-artifact-and-stream-msg/README.md` |
| `node-runtime` | `0x51ad820..0x51ad839` | 25 | 21/25 | 1 | serde Visitor::expecting (struct ValidatorL1StreamAction) (0x51ad820) | `research/work-items/RE-012-node115-artifact-and-stream-msg/README.md` |
| `node-runtime` | `0x292da70..0x292da89` | 25 | 21/25 | 1 | serde Visitor::expecting (struct ValidatorL1StreamTracker) (0x292da70) | `research/work-items/RE-012-node115-artifact-and-stream-msg/README.md` |
| `node-runtime` | `0x3c4d7f0..0x3c4d809` | 25 | 21/25 | 1 | serde Visitor::expecting (struct ValidatorL1StreamTracker) (0x3c4d7f0) | `research/work-items/RE-012-node115-artifact-and-stream-msg/README.md` |
| `node-runtime` | `0x4d9c190..0x4d9c1a9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct ValidatorL1StreamTracker) (0x4d9c190) | `research/work-items/RE-012-node115-artifact-and-stream-msg/README.md` |
| `vaults` | `0x292cf30..0x292cf49` | 25 | 21/25 | 1 | serde Visitor::expecting (struct Vault) (0x292cf30) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `vaults` | `0x44dc830..0x44dc849` | 25 | 21/25 | 1 | serde Visitor::expecting (struct Vault) (0x44dc830) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `vaults` | `0x4d9c670..0x4d9c689` | 25 | 21/25 | 1 | serde Visitor::expecting (struct Vault) (0x4d9c670) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `vaults` | `0x292dd90..0x292dda9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct VaultDistributeAction) (0x292dd90) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `vaults` | `0x4459ff0..0x445a009` | 25 | 21/25 | 1 | serde Visitor::expecting (struct VaultDistributeAction) (0x4459ff0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `vaults` | `0x53d5f90..0x53d5fa9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct VaultDistributeAction) (0x53d5f90) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `vaults` | `0x292d090..0x292d0a9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct VaultModifyAction) (0x292d090) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `vaults` | `0x4454be0..0x4454bf9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct VaultModifyAction) (0x4454be0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `vaults` | `0x53d61d0..0x53d61e9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct VaultModifyAction) (0x53d61d0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `vaults` | `0x292d910..0x292d929` | 25 | 21/25 | 1 | serde Visitor::expecting (struct VaultTransferAction) (0x292d910) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `vaults` | `0x4456370..0x4456389` | 25 | 21/25 | 1 | serde Visitor::expecting (struct VaultTransferAction) (0x4456370) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `vaults` | `0x53d66b0..0x53d66c9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct VaultTransferAction) (0x53d66b0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `fees` | `0x27733b0..0x27733c9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct VipFees) (0x27733b0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `fees` | `0x36ccf10..0x36ccf29` | 25 | 21/25 | 1 | serde Visitor::expecting (struct VipFees) (0x36ccf10) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `fees` | `0x5616d50..0x5616d69` | 25 | 21/25 | 1 | serde Visitor::expecting (struct VipFees) (0x5616d50) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `abci` | `0x29b03b0..0x29b03c9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct VoteAbciDigestAction) (0x29b03b0) | `research/work-items/RE-009-node115-storage-abci-byte-matches/README.md` |
| `abci` | `0x4459fd0..0x4459fe9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct VoteAbciDigestAction) (0x4459fd0) | `research/work-items/RE-009-node115-storage-abci-byte-matches/README.md` |
| `abci` | `0x5941e70..0x5941e89` | 25 | 21/25 | 1 | serde Visitor::expecting (struct VoteAbciDigestAction) (0x5941e70) | `research/work-items/RE-009-node115-storage-abci-byte-matches/README.md` |
| `bridge` | `0x292dd50..0x292dd69` | 25 | 21/25 | 1 | serde Visitor::expecting (struct VoteEthDepositAction) (0x292dd50) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `bridge` | `0x4692c80..0x4692c99` | 25 | 21/25 | 1 | serde Visitor::expecting (struct VoteEthDepositAction) (0x4692c80) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `bridge` | `0x5942670..0x5942689` | 25 | 21/25 | 1 | serde Visitor::expecting (struct VoteEthDepositAction) (0x5942670) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `bridge` | `0x29b06f0..0x29b0709` | 25 | 21/25 | 1 | serde Visitor::expecting (struct VoteEthFinalizedValidatorSetUpdateAction) (0x29b06f0) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `bridge` | `0x4468000..0x4468019` | 25 | 21/25 | 1 | serde Visitor::expecting (struct VoteEthFinalizedValidatorSetUpdateAction) (0x4468000) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `bridge` | `0x5942750..0x5942769` | 25 | 21/25 | 1 | serde Visitor::expecting (struct VoteEthFinalizedValidatorSetUpdateAction) (0x5942750) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `bridge` | `0x292d9f0..0x292da09` | 25 | 21/25 | 1 | serde Visitor::expecting (struct VoteEthFinalizedWithdrawalAction) (0x292d9f0) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `bridge` | `0x44662d0..0x44662e9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct VoteEthFinalizedWithdrawalAction) (0x44662d0) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `bridge` | `0x53d6530..0x53d6549` | 25 | 21/25 | 1 | serde Visitor::expecting (struct VoteEthFinalizedWithdrawalAction) (0x53d6530) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `abci` | `0x292dd70..0x292dd89` | 25 | 21/25 | 1 | serde Visitor::expecting (struct VoteL1HashAction) (0x292dd70) | `research/work-items/RE-009-node115-storage-abci-byte-matches/README.md` |
| `abci` | `0x4454ba0..0x4454bb9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct VoteL1HashAction) (0x4454ba0) | `research/work-items/RE-009-node115-storage-abci-byte-matches/README.md` |
| `abci` | `0x5942830..0x5942849` | 25 | 21/25 | 1 | serde Visitor::expecting (struct VoteL1HashAction) (0x5942830) | `research/work-items/RE-009-node115-storage-abci-byte-matches/README.md` |
| `orderbook` | `0x2d4a360..0x2d4a379` | 25 | 21/25 | 1 | serde Visitor::expecting (struct WaitingTwap) (0x2d4a360) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x38dbbe0..0x38dbbf9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct WaitingTwap) (0x38dbbe0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x5a2f090..0x5a2f0a9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct WaitingTwap) (0x5a2f090) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `action-wire` | `0x2420260..0x2420279` | 25 | 21/25 | 1 | serde Visitor::expecting (struct WithdrawAction3) (0x2420260) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `action-wire` | `0x4451b30..0x4451b49` | 25 | 21/25 | 1 | serde Visitor::expecting (struct WithdrawAction3) (0x4451b30) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `action-wire` | `0x59425f0..0x5942609` | 25 | 21/25 | 1 | serde Visitor::expecting (struct WithdrawAction3) (0x59425f0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `storage` | `0x25eb5b0..0x25eb5c9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct variant EvmDbSerde::NoEvmDb) (0x25eb5b0) | `research/work-items/RE-009-node115-storage-abci-byte-matches/README.md` |
| `storage` | `0x38dbb60..0x38dbb79` | 25 | 21/25 | 1 | serde Visitor::expecting (struct variant EvmDbSerde::NoEvmDb) (0x38dbb60) | `research/work-items/RE-009-node115-storage-abci-byte-matches/README.md` |
| `storage` | `0x50d95e0..0x50d95f9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct variant EvmDbSerde::NoEvmDb) (0x50d95e0) | `research/work-items/RE-009-node115-storage-abci-byte-matches/README.md` |
| `storage` | `0x27731f0..0x2773209` | 25 | 21/25 | 1 | serde Visitor::expecting (struct variant FileSnapshotRequest::L4Snapshots) (0x27731f0) | `research/work-items/RE-009-node115-storage-abci-byte-matches/README.md` |
| `transport` | `0x292d5f0..0x292d609` | 25 | 21/25 | 1 | serde Visitor::expecting (struct variant GossipPriorityGasAuctionChange::EnableAndRestart) (0x292d5f0) | `research/work-items/RE-012-node115-gossip-rpc-connections-local-state/README.md` |
| `transport` | `0x46dd950..0x46dd969` | 25 | 21/25 | 1 | serde Visitor::expecting (struct variant GossipPriorityGasAuctionChange::EnableAndRestart) (0x46dd950) | `research/work-items/RE-012-node115-gossip-rpc-connections-local-state/README.md` |
| `transport` | `0x53d67d0..0x53d67e9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct variant GossipPriorityGasAuctionChange::EnableAndRestart) (0x53d67d0) | `research/work-items/RE-012-node115-gossip-rpc-connections-local-state/README.md` |
| `evm-rpc` | `0x174c6f0..0x174c709` | 25 | 21/25 | 1 | serde Visitor::expecting (struct variant JsonRpcResult::Error) (0x174c6f0) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `evm-rpc` | `0x174c750..0x174c769` | 25 | 21/25 | 1 | serde Visitor::expecting (struct variant JsonRpcResult::Success) (0x174c750) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `dex-registry` | `0x2c7d0b0..0x2c7d0c9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct variant MainOrHip3::Hip3) (0x2c7d0b0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `dex-registry` | `0x44dcc30..0x44dcc49` | 25 | 21/25 | 1 | serde Visitor::expecting (struct variant MainOrHip3::Hip3) (0x44dcc30) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `dex-registry` | `0x5616db0..0x5616dc9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct variant MainOrHip3::Hip3) (0x5616db0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `dex-registry` | `0x2c7cc40..0x2c7cc59` | 25 | 21/25 | 1 | serde Visitor::expecting (struct variant MainOrHip3::Main) (0x2c7cc40) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `dex-registry` | `0x44dc330..0x44dc349` | 25 | 21/25 | 1 | serde Visitor::expecting (struct variant MainOrHip3::Main) (0x44dc330) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `dex-registry` | `0x56168b0..0x56168c9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct variant MainOrHip3::Main) (0x56168b0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `info-api` | `0x27737f0..0x2773809` | 25 | 21/25 | 1 | serde Visitor::expecting (struct variant NodeInfoRequest::ActiveAssetData) (0x27737f0) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `info-api` | `0x2773a30..0x2773a49` | 25 | 21/25 | 1 | serde Visitor::expecting (struct variant NodeInfoRequest::ApprovedBuilders) (0x2773a30) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `info-api` | `0x2773d70..0x2773d89` | 25 | 21/25 | 1 | serde Visitor::expecting (struct variant NodeInfoRequest::Aqav2InterestHistory) (0x2773d70) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `info-api` | `0x2773690..0x27736a9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct variant NodeInfoRequest::BoleReserveState) (0x2773690) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `info-api` | `0x2773b10..0x2773b29` | 25 | 21/25 | 1 | serde Visitor::expecting (struct variant NodeInfoRequest::BoleUserState) (0x2773b10) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `info-api` | `0x2773910..0x2773929` | 25 | 21/25 | 1 | serde Visitor::expecting (struct variant NodeInfoRequest::ClearinghouseState) (0x2773910) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `info-api` | `0x2772fd0..0x2772fe9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct variant NodeInfoRequest::Delegations) (0x2772fd0) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `info-api` | `0x2773c10..0x2773c29` | 25 | 22/25 | 1 | serde Visitor::expecting (struct variant NodeInfoRequest::DelegatorSummary) (0x2773c10) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `info-api` | `0x2773930..0x2773949` | 25 | 21/25 | 1 | serde Visitor::expecting (struct variant NodeInfoRequest::ExtraAgents) (0x2773930) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `info-api` | `0x27735f0..0x2773609` | 25 | 21/25 | 1 | serde Visitor::expecting (struct variant NodeInfoRequest::FileSnapshot) (0x27735f0) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `info-api` | `0x2773830..0x2773849` | 25 | 21/25 | 1 | serde Visitor::expecting (struct variant NodeInfoRequest::FrontendOpenOrders) (0x2773830) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `info-api` | `0x27733d0..0x27733e9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct variant NodeInfoRequest::LeadingVaults) (0x27733d0) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `info-api` | `0x2773d90..0x2773da9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct variant NodeInfoRequest::MarginTable) (0x2773d90) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `info-api` | `0x2773e90..0x2773ea9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct variant NodeInfoRequest::MaxBuilderFee) (0x2773e90) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `info-api` | `0x27739f0..0x2773a09` | 25 | 21/25 | 1 | serde Visitor::expecting (struct variant NodeInfoRequest::Meta) (0x27739f0) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `info-api` | `0x2774010..0x2774029` | 25 | 21/25 | 1 | serde Visitor::expecting (struct variant NodeInfoRequest::OpenOrders) (0x2774010) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `info-api` | `0x2773f50..0x2773f69` | 25 | 21/25 | 1 | serde Visitor::expecting (struct variant NodeInfoRequest::OutcomeDeployerLimits) (0x2773f50) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `info-api` | `0x2773570..0x2773589` | 25 | 21/25 | 1 | serde Visitor::expecting (struct variant NodeInfoRequest::PerpAnnotation) (0x2773570) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `info-api` | `0x2773a70..0x2773a89` | 25 | 21/25 | 1 | serde Visitor::expecting (struct variant NodeInfoRequest::PerpDexLimits) (0x2773a70) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `info-api` | `0x2773bd0..0x2773be9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct variant NodeInfoRequest::PerpDexStatus) (0x2773bd0) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `info-api` | `0x2773530..0x2773549` | 25 | 21/25 | 1 | serde Visitor::expecting (struct variant NodeInfoRequest::PerpsAtOpenInterestCap) (0x2773530) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `info-api` | `0x2773410..0x2773429` | 25 | 21/25 | 1 | serde Visitor::expecting (struct variant NodeInfoRequest::SettledOutcome) (0x2773410) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `info-api` | `0x27736f0..0x2773709` | 25 | 21/25 | 1 | serde Visitor::expecting (struct variant NodeInfoRequest::SettledQuestion) (0x27736f0) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `info-api` | `0x2773fd0..0x2773fe9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct variant NodeInfoRequest::SpotClearinghouseState) (0x2773fd0) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `info-api` | `0x2773030..0x2773049` | 25 | 21/25 | 1 | serde Visitor::expecting (struct variant NodeInfoRequest::SpotDeployState) (0x2773030) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `info-api` | `0x2773ff0..0x2774009` | 25 | 21/25 | 1 | serde Visitor::expecting (struct variant NodeInfoRequest::SpotMeta) (0x2773ff0) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `info-api` | `0x27732f0..0x2773309` | 25 | 21/25 | 1 | serde Visitor::expecting (struct variant NodeInfoRequest::SubAccounts) (0x27732f0) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `info-api` | `0x27732d0..0x27732e9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct variant NodeInfoRequest::SubAccounts2) (0x27732d0) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `info-api` | `0x2773cf0..0x2773d09` | 25 | 21/25 | 1 | serde Visitor::expecting (struct variant NodeInfoRequest::TokenAnnotation) (0x2773cf0) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `info-api` | `0x2773f10..0x2773f29` | 25 | 21/25 | 1 | serde Visitor::expecting (struct variant NodeInfoRequest::UserAbstraction) (0x2773f10) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `info-api` | `0x2773090..0x27730a9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct variant NodeInfoRequest::UserDexAbstraction) (0x2773090) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `info-api` | `0x2773230..0x2773249` | 25 | 21/25 | 1 | serde Visitor::expecting (struct variant NodeInfoRequest::UserFees) (0x2773230) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `info-api` | `0x27731d0..0x27731e9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct variant NodeInfoRequest::UserRateLimit) (0x27731d0) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `info-api` | `0x2773190..0x27731a9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct variant NodeInfoRequest::UserRole) (0x2773190) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `info-api` | `0x2774030..0x2774049` | 25 | 21/25 | 1 | serde Visitor::expecting (struct variant NodeInfoRequest::UserStarState) (0x2774030) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `info-api` | `0x2773290..0x27732a9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct variant NodeInfoRequest::UserToMultiSigSigners) (0x2773290) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `info-api` | `0x2773270..0x2773289` | 25 | 21/25 | 1 | serde Visitor::expecting (struct variant NodeInfoRequest::UserVaultEquities) (0x2773270) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `info-api` | `0x2773310..0x2773329` | 25 | 21/25 | 1 | serde Visitor::expecting (struct variant NodeInfoRequest::VaultSummaries) (0x2773310) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `info-api` | `0x2773f30..0x2773f49` | 25 | 21/25 | 1 | serde Visitor::expecting (struct variant NodeInfoRequest::Votes) (0x2773f30) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `info-api` | `0x2773770..0x2773789` | 25 | 21/25 | 1 | serde Visitor::expecting (struct variant NodeInfoRequest::WebData2) (0x2773770) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `info-api` | `0x2773a50..0x2773a69` | 25 | 21/25 | 1 | serde Visitor::expecting (struct variant NodeInfoRequest::WebData3) (0x2773a50) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `evm` | `0x26a1950..0x26a1969` | 25 | 21/25 | 1 | serde Visitor::expecting (struct variant ReadPrecompileResult::Ok) (0x26a1950) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `evm` | `0x5b09190..0x5b091a9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct variant ReadPrecompileResult::Ok) (0x5b09190) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `transport` | `0x292d6b0..0x292d6c9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct variant SetGossipPriority::Params) (0x292d6b0) | `research/work-items/RE-012-node115-gossip-rpc-connections-local-state/README.md` |
| `transport` | `0x46ddd90..0x46ddda9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct variant SetGossipPriority::Params) (0x46ddd90) | `research/work-items/RE-012-node115-gossip-rpc-connections-local-state/README.md` |
| `transport` | `0x53d60b0..0x53d60c9` | 25 | 21/25 | 1 | serde Visitor::expecting (struct variant SetGossipPriority::Params) (0x53d60b0) | `research/work-items/RE-012-node115-gossip-rpc-connections-local-state/README.md` |
| `abci` | `0x292d2b0..0x292d2c9` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct AbciDigest) (0x292d2b0) | `research/work-items/RE-009-node115-storage-abci-byte-matches/README.md` |
| `abci` | `0x41c6970..0x41c6989` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct AbciDigest) (0x41c6970) | `research/work-items/RE-009-node115-storage-abci-byte-matches/README.md` |
| `abci` | `0x53d5ab0..0x53d5ac9` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct AbciDigest) (0x53d5ab0) | `research/work-items/RE-009-node115-storage-abci-byte-matches/README.md` |
| `exchange` | `0x2773a90..0x2773aa9` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct AbstractionReturns) (0x2773a90) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `exchange` | `0x44dc690..0x44dc6a9` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct AbstractionReturns) (0x44dc690) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `exchange` | `0x5b096d0..0x5b096e9` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct AbstractionReturns) (0x5b096d0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `risk` | `0x25eb430..0x25eb449` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct BoleToken) (0x25eb430) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `risk` | `0x4229520..0x4229539` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct BoleToken) (0x4229520) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `risk` | `0x4d9c8e0..0x4d9c8f9` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct BoleToken) (0x4d9c8e0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `orderbook` | `0x2420a80..0x2420a99` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct BookOrderKey) (0x2420a80) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x452a1a0..0x452a1b9` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct BookOrderKey) (0x452a1a0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x5942710..0x5942729` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct BookOrderKey) (0x5942710) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x452a100..0x452a119` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct BookOrders) (0x452a100) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x5941e30..0x5941e49` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct BookOrders) (0x5941e30) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x26a1820..0x26a1839` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct Books) (0x26a1820) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x3f14690..0x3f146a9` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct Books) (0x3f14690) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x5942070..0x5942089` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct Books) (0x5942070) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `bridge` | `0x25eb4b0..0x25eb4c9` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct BridgeEpoch) (0x25eb4b0) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `bridge` | `0x44dca10..0x44dca29` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct BridgeEpoch) (0x44dca10) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `bridge` | `0x53d6350..0x53d6369` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct BridgeEpoch) (0x53d6350) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `bridge` | `0x25eb4d0..0x25eb4e9` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct BridgeValidator) (0x25eb4d0) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `bridge` | `0x44dc930..0x44dc949` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct BridgeValidator) (0x44dc930) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `bridge` | `0x53d5890..0x53d58a9` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct BridgeValidator) (0x53d5890) | `research/work-items/RE-015-node115-stream-f-byte-matches/README.md` |
| `orderbook` | `0x26a15d0..0x26a15e9` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct Cloid) (0x26a15d0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x4229790..0x42297a9` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct Cloid) (0x4229790) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x53d5ad0..0x53d5ae9` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct Cloid) (0x53d5ad0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `fees` | `0x292dcf0..0x292dd09` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct CollectedBuilderFees) (0x292dcf0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `fees` | `0x3c4d4b0..0x3c4d4c9` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct CollectedBuilderFees) (0x3c4d4b0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `fees` | `0x5616810..0x5616829` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct CollectedBuilderFees) (0x5616810) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `fees` | `0x292d7b0..0x292d7c9` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct DailyScaledVlms) (0x292d7b0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `fees` | `0x36cd430..0x36cd449` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct DailyScaledVlms) (0x36cd430) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `fees` | `0x4d9c530..0x4d9c549` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct DailyScaledVlms) (0x4d9c530) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `fees` | `0x2772fb0..0x2772fc9` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct FeeRateMapSerde) (0x2772fb0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `fees` | `0x36cd3f0..0x36cd409` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct FeeRateMapSerde) (0x36cd3f0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `fees` | `0x5616890..0x56168a9` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct FeeRateMapSerde) (0x5616890) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `l1-shared` | `0x2c7d010..0x2c7d029` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct FpDecimal) (0x2c7d010) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `l1-shared` | `0x4229420..0x4229439` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct FpDecimal) (0x4229420) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `l1-shared` | `0x53d6250..0x53d6269` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct FpDecimal) (0x53d6250) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `l1-shared` | `0x292d210..0x292d229` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct NonceSetDe) (0x292d210) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `l1-shared` | `0x4229930..0x4229949` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct NonceSetDe) (0x4229930) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `l1-shared` | `0x5b08df0..0x5b08e09` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct NonceSetDe) (0x5b08df0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `assets` | `0x25eba00..0x25eba19` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct Ntl) (0x25eba00) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `assets` | `0x46de1b0..0x46de1c9` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct Ntl) (0x46de1b0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `assets` | `0x50d8d10..0x50d8d29` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct Ntl) (0x50d8d10) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `assets` | `0x25eb7e0..0x25eb7f9` | 25 | 22/25 | 1 | serde Visitor::expecting (tuple struct Ntli) (0x25eb7e0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `assets` | `0x46de390..0x46de3a9` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct Ntli) (0x46de390) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `assets` | `0x50d8f30..0x50d8f49` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct Ntli) (0x50d8f30) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `risk` | `0x22f5ae0..0x22f5af9` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct OracleKindMap) (0x22f5ae0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `risk` | `0x3d527d0..0x3d527e9` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct OracleKindMap) (0x3d527d0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `risk` | `0x53d5f10..0x53d5f29` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct OracleKindMap) (0x53d5f10) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `risk` | `0x24a7e50..0x24a7e69` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct OutcomeDeployer) (0x24a7e50) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `risk` | `0x42290c0..0x42290d9` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct OutcomeDeployer) (0x42290c0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `risk` | `0x53d5c10..0x53d5c29` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct OutcomeDeployer) (0x53d5c10) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `assets` | `0x2c7d570..0x2c7d589` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct Pdi) (0x2c7d570) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `assets` | `0x452a140..0x452a159` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct Pdi) (0x452a140) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `assets` | `0x4d9c5f0..0x4d9c609` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct Pdi) (0x4d9c5f0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `dex-registry` | `0x292d8f0..0x292d909` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct PerpDexs) (0x292d8f0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `dex-registry` | `0x4229060..0x4229079` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct PerpDexs) (0x4229060) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `dex-registry` | `0x53d5e90..0x53d5ea9` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct PerpDexs) (0x53d5e90) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `assets` | `0x26a1cb0..0x26a1cc9` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct Px) (0x26a1cb0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `assets` | `0x3f14730..0x3f14749` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct Px) (0x3f14730) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `assets` | `0x57d1af0..0x57d1b09` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct Px) (0x57d1af0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `risk` | `0x25ebab0..0x25ebac9` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct RawLeverage) (0x25ebab0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `risk` | `0x42295f0..0x4229609` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct RawLeverage) (0x42295f0) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `risk` | `0x5b09210..0x5b09229` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct RawLeverage) (0x5b09210) | `research/work-items/RE-007-node115-stream-e2-byte-matches/README.md` |
| `fees` | `0x2c7cd40..0x2c7cd59` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct RawVlm) (0x2c7cd40) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `fees` | `0x4229480..0x4229499` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct RawVlm) (0x4229480) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `fees` | `0x57d1990..0x57d19a9` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct RawVlm) (0x57d1990) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `fees` | `0x292da30..0x292da49` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct ScaledVlm) (0x292da30) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `fees` | `0x46dd8d0..0x46dd8e9` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct ScaledVlm) (0x46dd8d0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `fees` | `0x56169d0..0x56169e9` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct ScaledVlm) (0x56169d0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `assets` | `0x22f56c0..0x22f56d9` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct SideMap) (0x22f56c0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `assets` | `0x46dd8f0..0x46dd909` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct SideMap) (0x46dd8f0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `assets` | `0x50d8e90..0x50d8ea9` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct SideMap) (0x50d8e90) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `assets` | `0x26a1450..0x26a1469` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct Sz) (0x26a1450) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `assets` | `0x4228f90..0x4228fa9` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct Sz) (0x4228f90) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `assets` | `0x57d1890..0x57d18a9` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct Sz) (0x57d1890) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `assets` | `0x26a1890..0x26a18a9` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct Szi) (0x26a1890) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `assets` | `0x4229690..0x42296a9` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct Szi) (0x4229690) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `assets` | `0x57d19f0..0x57d1a09` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct Szi) (0x57d19f0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `assets` | `0x292d9d0..0x292d9e9` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct TokenInfos) (0x292d9d0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `assets` | `0x3c4d230..0x3c4d249` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct TokenInfos) (0x3c4d230) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `assets` | `0x5a2f490..0x5a2f4a9` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct TokenInfos) (0x5a2f490) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x2d4a100..0x2d4a119` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct TwapId) (0x2d4a100) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x38dbae0..0x38dbaf9` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct TwapId) (0x38dbae0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `orderbook` | `0x5a2f250..0x5a2f269` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct TwapId) (0x5a2f250) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `assets` | `0x25eb800..0x25eb819` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct UsdcBigSpotNtl) (0x25eb800) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `assets` | `0x46de230..0x46de249` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct UsdcBigSpotNtl) (0x46de230) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `assets` | `0x50d9520..0x50d9539` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct UsdcBigSpotNtl) (0x50d9520) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `assets` | `0x25eb920..0x25eb939` | 25 | 22/25 | 1 | serde Visitor::expecting (tuple struct UsdcNtl) (0x25eb920) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `assets` | `0x46dd970..0x46dd989` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct UsdcNtl) (0x46dd970) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `assets` | `0x50d8e70..0x50d8e89` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct UsdcNtl) (0x50d8e70) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `assets` | `0x25ebcc0..0x25ebcd9` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct UsdcNtlScaleSerde) (0x25ebcc0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `assets` | `0x46de1d0..0x46de1e9` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct UsdcNtlScaleSerde) (0x46de1d0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `assets` | `0x50d9400..0x50d9419` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct UsdcNtlScaleSerde) (0x50d9400) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `assets` | `0x25eb880..0x25eb899` | 25 | 22/25 | 1 | serde Visitor::expecting (tuple struct UsdcNtli) (0x25eb880) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `assets` | `0x46ddcf0..0x46ddd09` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct UsdcNtli) (0x46ddcf0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `assets` | `0x50d90e0..0x50d90f9` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct UsdcNtli) (0x50d90e0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `assets` | `0x26a19d0..0x26a19e9` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct UsdcPx) (0x26a19d0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `assets` | `0x3f14750..0x3f14769` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct UsdcPx) (0x3f14750) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `assets` | `0x57d1a10..0x57d1a29` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct UsdcPx) (0x57d1a10) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `assets` | `0x25eb820..0x25eb839` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct UsdcRoughNtli) (0x25eb820) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `assets` | `0x46ddc50..0x46ddc69` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct UsdcRoughNtli) (0x46ddc50) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `assets` | `0x50d9270..0x50d9289` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct UsdcRoughNtli) (0x50d9270) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `assets` | `0x26a16e0..0x26a16f9` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct Wei) (0x26a16e0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `assets` | `0x43514a0..0x43514b9` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct Wei) (0x43514a0) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `assets` | `0x4e39740..0x4e39759` | 25 | 21/25 | 1 | serde Visitor::expecting (tuple struct Wei) (0x4e39740) | `research/work-items/RE-004-node115-stream-e1-byte-matches/README.md` |
| `abci` | `0x2420960..0x2420979` | 25 | 21/25 | 1 | serde Visitor::expecting (unit struct ColdHardQuorumPolicy) (0x2420960) | `research/work-items/RE-009-node115-storage-abci-byte-matches/README.md` |
| `abci` | `0x42297b0..0x42297c9` | 25 | 21/25 | 1 | serde Visitor::expecting (unit struct ColdHardQuorumPolicy) (0x42297b0) | `research/work-items/RE-009-node115-storage-abci-byte-matches/README.md` |
| `abci` | `0x53d63d0..0x53d63e9` | 25 | 21/25 | 1 | serde Visitor::expecting (unit struct ColdHardQuorumPolicy) (0x53d63d0) | `research/work-items/RE-009-node115-storage-abci-byte-matches/README.md` |
| `abci` | `0x2773c90..0x2773ca9` | 25 | 21/25 | 1 | serde Visitor::expecting (unit struct NoopHardQuorumPolicy) (0x2773c90) | `research/work-items/RE-009-node115-storage-abci-byte-matches/README.md` |
| `abci` | `0x4229140..0x4229159` | 25 | 21/25 | 1 | serde Visitor::expecting (unit struct NoopHardQuorumPolicy) (0x4229140) | `research/work-items/RE-009-node115-storage-abci-byte-matches/README.md` |
| `abci` | `0x5942450..0x5942469` | 25 | 21/25 | 1 | serde Visitor::expecting (unit struct NoopHardQuorumPolicy) (0x5942450) | `research/work-items/RE-009-node115-storage-abci-byte-matches/README.md` |

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
