# bridge: complete node #115 `BridgeRequest` 8-tag ABI/Agent signing map and `bridge` crate integration

This packet closes the remaining `l1/src/bridge_request.rs` variants (tags `0..=7` in `0x4526230`, jump table `0x7d3708`), binds all seven `l1/src/bridge2.rs` / `l1/src/bridge_request.rs` panic `Location` records and their enclosing FDEs, and joins all five existing node #115 bridge micro-crates into `src/bridge/`.

- Component ID: `bridge` (`l1/bridge2.rs`, `l1/bridge_request.rs`).
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (`artifacts/node/115/hl-node`).
- Claim status:
  - **Observation**: ELF section bounds, all 8 jump-table slots at `0x7d3708`, all 7 `R_X86_64_RELATIVE` panic `Location` records (`l1/src/bridge2.rs` lines 145, 147, 177, 178, 385, 477 and `l1/src/bridge_request.rs` line 83), `.rodata` ABI labels (`modify`, `Locker`, `Finalizer`, `changeDisputePeriodSeconds`, `changeBlockDurationMillis`, `changeLockerThreshold`, `updateValidatorSet`, `requestWithdrawal`, `unlock`, `invalidateWithdrawals`, `Bridge2`, `bridge2 withdrawal balance bug`), Arbitrum EIP-712 chain-ID immediates `0xa4b1` (42161) / `0x66eee` (421614) in `0x4526e40`, and full FDE extents + SHA-256 hashes for all 7 bridge FDEs.
  - **Inference**: Rust enum/struct names (`BridgeRequest`, `BridgeRole`, `BridgeAgentPayload`, `EthEventId`, `VoteEthDepositAction`) and Solidity ABI parameter names.
  - **Unresolved**: Full validator-quorum signature aggregation inside `0x44d7b10`/`0x44d7f10`, live Bridge2 contract address table population inside `0x1546aa0`, deposit pruning/ring maintenance inside `0x5afedf0`, and whole-crate `rustc 1.95.0` codegen identity.
- Captured code executed: `false`. Static binary analysis + independently authored MIT Rust tests only.
- Progress gate: no automatic gate flip claimed in this packet.

## All 8 `BridgeRequest` tags in `0x4526230` (jump table `0x7d3708`)

| Tag | Arm VA | ABI Encoder | Observed Label / Tuple Shape (`ethabi::Token` tags) |
| --- | --- | --- | --- |
| 0 | `0x4526257` | `0x44e82d0` | `(string "modify{Locker\|Finalizer}", (address,), bool, uint64)` (`[6, 9([0]), 5, 4]`; `0x457cf20` formats role) |
| 1 | `0x45266ac` | `0x44e6980` | `(string "changeDisputePeriodSeconds", uint64, uint64)` (`[6, 4, 4]`) |
| 2 | `0x45263bb` | `0x44e6980` | `(string "changeBlockDurationMillis", uint64, uint64)` (`[6, 4, 4]`) |
| 3 | `0x45264fc` | `0x44e6980` | `(string "changeLockerThreshold", uint64, uint64)` (`[6, 4, 4]`) |
| 4 | `0x45263aa` | `0x3676390` -> `0x44e8f00` | `(string "updateValidatorSet", uint64 epoch, address[], address[], uint64[])` (`[6, 4, 8([0]), 8([0]), 8([4])]`) |
| 5 | `0x45267ed` | `0x44e96a0` | `(string "requestWithdrawal", address, address, uint64, uint64)` (`[6, 0, 0, 4, 4]`, 224 bytes) |
| 6 | `0x452695a` | `0x44ea040` | `(string "unlock", uint64 epoch, address[], address[], uint64[], uint64 nonce)` (`[6, 4, 8([0]), 8([0]), 8([4]), 4]`) |
| 7 | `0x4526640` | `0x44e6c40` | `(string "invalidateWithdrawals", bytes32[], uint64 nonce)` (`[6, 8([1]), 4]`) |

Outer wrapper `0x4526e40` computes `inner = keccak256(abi_encode(req))`, formats `"Bridge2{chain}"` via `Chain::fmt` (`0x1778c60`), looks up the 20-byte Bridge2 address (`0x1546aa0`, panicking at `l1/src/bridge_request.rs:83:78` if absent), builds `zero12 || contract20 || inner32` (`0x4302cd0`), hashes via Keccak-256 (`0x5cda910`/`0x5cdad40`), and emits `{ source: "a", connection_id, arb_chain_id: 0xa4b1 (Mainnet) | 0x66eee (other) }`.

## Reproduce

```sh
CARGO_BUILD_JOBS=4 RUST_TEST_THREADS=4 CARGO_TARGET_DIR=work/target/evm-bridge-api \
  cargo test --offline --locked --manifest-path src/bridge/Cargo.toml
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_bridge_crate_115 -v
```
