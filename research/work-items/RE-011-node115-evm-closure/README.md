# RE-011: Node #115 `evm` Full-Scope Closure (`l1/src/evm/*.rs`)

- **Target**: Linux x86-64 node #115 (`artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).
- **Component**: `evm` (`l1/evm/*`).
- **Closure Status**: Full static inventory and behavioral closure ready for strict `docs/SCOPE.md` joint `mapped`/`built`/`behavior` gate review (`identity` remains `false`).

## Complete Inventory Authenticated Directly Against Node #115

- **Source files**: **4/4** `l1/src/evm/*.rs` files (`evm_db.rs`, `evm_state.rs`, `hash.rs`, `hyper_evm.rs`, exact match with `research/imported/hl-node-115.inventory.json`).
- **Panic `Location` structs**: **9/9** `.data.rel.ro` entries (`evm_db.rs` 3, `evm_state.rs` 1, `hash.rs` 1, `hyper_evm.rs` 4; **0 unreferenced**).
- **FDE coverage**: **10/10** Location-referencing `.text` FDEs (`83,860 B`) + **20/20** disjoint companion business/serde FDEs (`27,681 B`: read precompile dispatcher/provider/enumerator, 7-address scaled precompile selector, dual-block gas & scaled activation, system contract installer, `CoreWriter` v1 `RawAction` parser, `0x0809` `L1BlockNumber` callback, `lt_hashes.json` writer, mode-13 intrinsic gas & admission, `HypeSystem` `Received` parser, and all 8 live-compiled `HyperEvm` serde FDEs from `RE-011-node115-stream-f-logic-byte-matches`) = **30 unique FDEs (`111,541 B`)** verified against `work/index/node-115-fde.tsv`.
- **Binary anchors verified**:
  - **10 `.text` instruction anchors**: dual-block gas limits (`3,000,000` / `30,000,000`) at `0x433dd30` and `0x2a1e37b`, `CoreWriter` length `<= 1000` (`0x38bf48f`), version `== 1` (`0x38bf508`), action ID `1..=17` (`0x38bf512`), read precompile `input_len <= 2000` (`0x38e3b4e`) and `1000 + 33 * len` gas (`0x38e3b5d`), `LtHash` `0x810`-byte struct copy (`0x38c25e8`), scaled precompile `0x01` match (`0x46a0eb3`), and mode-13 CREATE `32,000` gas (`0x5be2578`).
  - **3/3 embedded HyperEVM system contracts**: `CoreWriter` (`0x33*20`, 544 B @ `0x7a08f9`), `HypeSystem` (`0x22*20`, 122 B @ `0x7a0b31`), `WHype` (`0x55*20`, 2,041 B @ `0x7a0be5`), all addresses and SHA-256 digests authenticated directly from `.rodata`.
  - **4 `.rodata` string literals** (`build_small_evm_block_and_apply_l1_effects`, `build_big_evm_block_and_apply_l1_effects`, `RawAction(address,bytes)`, `Received(address,uint256)`) and **2 `.rodata` f64 guard pairs** (`(0.03, 0.07)` @ `0x4554f0`, `(0.05, 0.05)` @ `0x453520`).
- **Honest compiled-byte identity status**: `identity_gate_satisfied: false`. Landed first-party compiled-byte windows for `evm` remain tracked separately in `research/byte-windows.json` (`69` windows / `11,174 B`) and `research/work-items/RE-011-node115-stream-f-logic-byte-matches` (`8` disjoint FDEs / `8,689 B`).

## 1-to-1 Source File Mapping (All 10 Registered `evm` Crates)

| Node #115 Source File | Locations | Implementation Paths |
| --- | ---: | --- |
| `l1/src/evm/evm_db.rs` | 3 | `src/evm/src/lt_hash.rs`, `src/node115-storage-value-decode/lib.rs` |
| `l1/src/evm/evm_state.rs` | 1 | `src/evm/src/gas.rs`, `src/node115-sstore-warm/lib.rs`, `src/node115-transient-rollback-branches/lib.rs`, `src/node115-child-reserve-fold/lib.rs`, `src/node115-bole-reserve-reply/lib.rs`, `src/node115-bole-user-reply/lib.rs` |
| `l1/src/evm/hash.rs` | 1 | `src/evm/src/lt_hash.rs` |
| `l1/src/evm/hyper_evm.rs` | 4 | `src/evm/src/{lib,precompiles,system}.rs`, `src/node115-evm-precompile-outcome-names/src/lib.rs`, `src/node115-evm-tx-type-names/src/lib.rs`, `src/node115-read-precompile-result/src/lib.rs` |

## Verification

```bash
(cd research/work-items/RE-011-node115-evm-closure && sha256sum -c MANIFEST.sha256)
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-011-node115-evm-closure/verify.py --self-test
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_evm_closure_115 -v
CARGO_BUILD_JOBS=4 RUST_TEST_THREADS=4 cargo +1.95.0 test --offline --locked --manifest-path src/evm/Cargo.toml
```
