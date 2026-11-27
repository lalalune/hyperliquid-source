# RE-008: Node #115 CStaking Withdrawal Queue (`0x3c3bbd0`, `0x36cb770`, `0x3c3b790`)

## Scope & Target

- **Target binary**: Linux x86-64 node #115 (`artifacts/node/115/hl-node`)
- **SHA-256**: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- **Component**: `staking` (`RE-008`)
- **Integrated Rust crate**: `src/node115-staking` (`src/withdrawal_queue.rs`)
- **Static analysis only**: No captured binary execution; all bytes and `.rodata` constants are read statically.

## Direct Binary Observations

| Function | FDE Extent | Size | Verified Mechanics |
| --- | --- | --- | --- |
| `c_staking_queue_withdrawal` | `0x3c3bbd0..0x3c3bf47` | 887 B | Checks user's optional long-term lockup timestamp (`[r13+8..0x14]`); if active and `now < lockup_until`, rejects with `0x141` (`Action not allowed while staking long term`), else clears expired lockup. Checks `pending_amount + amount` does not overflow and is `<= withdrawable_balance` (`0x64e7b50`), else rejects with `0x142` (`Insufficient balance to withdraw from CStaking`). Loads liquid balance from `[state+0x228]` and invokes `0x36cb770`. |
| `withdrawal_queue_enqueue` | `0x36cb770..0x36cba51` | 737 B | Looks up user's pending summary `(pending_wei, pending_count)` in `[queue+0x20]` (`[state+0x268]`). Rejects `pending_count > 4` (max 5 concurrent withdrawals per user) with `0x143` (`Too many concurrent CStaking withdrawals`). Rejects `pending_wei + amount` overflow or `> liquid_balance` with `0x142` (`0xc3` on accumulator overflow). Computes maturity `now + delay` using `.rodata 0x450d00`: **`604,800.0` s** (7 days) on `Local`/`Mainnet` (`0x4122750000000000`), **`300.0` s** (5 minutes) on `Sandbox`/`Testnet` (`0x4072c00000000000`). Appends 32-byte `(wei: u64, user: [u8; 20])` entry to the bucket at maturity time and returns `0x1a2`. |
| `c_staking_drain_withdrawals` | `0x3c3b790..0x3c3b8d5` | 325 B | Splits `[state+0x248]` time-ordered queue at `now` (`0x3cec4e0`), decrements `[state+0x268]` pending summaries (`0x3d70460`), and subtracts completed withdrawal amounts from `[state+0x228]` user balances (`0x3d5dfb0`). |

## Inferences & Remaining Unknowns

- **Inferences**:
  - `dec bpl; cmp bpl, 2; setb al` at `0x36cb893..0x36cb89c` maps `Chain::Sandbox (1)` and `Chain::Testnet (2)` to index `1` (`300.0s`) and `Chain::Local (0)` and `Chain::Mainnet (3)` to index `0` (`604,800.0s`).
- **Unknowns (explicitly not claimed)**:
  - Spot-account crediting after `c_staking_drain_withdrawals` returns completed payouts belongs to the L1 exchange/spot clearinghouse layer outside `c_staking`.

## Reproduction

```bash
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-008-node115-staking-withdrawal-queue/verify.py
(cd research/work-items/RE-008-node115-staking-withdrawal-queue && sha256sum -c MANIFEST.sha256)
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_node115_staking_withdrawal_queue -v
CARGO_BUILD_JOBS=4 RUST_TEST_THREADS=4 cargo test --offline --locked --manifest-path src/node115-staking/Cargo.toml
```
