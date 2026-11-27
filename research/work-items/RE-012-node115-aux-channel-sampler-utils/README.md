# RE-012 — Node #115 `aux`, `channel`, `group_and_seq_sampler`, and `utils` Completion Map

- **Target**: Linux x86-64 node `#115` (`artifacts/node/115/hl-node`), SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- **Component**: `node-runtime` (`RE-012`), crate `src/node-runtime` (`src/aux.rs`).
- **Coverage Milestone**: Completes binary-backed mapping and reconstruction of all **21/21 (100%)** non-consensus `node/src/*.rs` source files in node #115 (alongside **12/12** `net_utils/src/*.rs` and **4/4** `z_forks/bincode-fork` source files).

## Binary-Backed Findings

1. **`node/src/aux.rs`** (`.rodata 0x4482a4`, `Location 0x64a3660` L262:13, FDE `0x51cf360..0x51d0f70`, 7,184 B):
   - Enumerates all 10 auxiliary output streams in exact initialization order (`0x91fcc0..0x91fd5e` + `0x91c33c`):
     `node_trades`, `node_fills`, `node_twap_statuses`, `node_raw_book_diffs`, `node_order_statuses`, `misc_events`, `hip3_oracle_updates`, `system_and_core_writer_actions`, `evm_block_and_receipts`, `dex_user_clearinghouse_states`.
   - Enforces the mutual-exclusion panic invariant at `0x51d0aba`: `"cannot set both batch_by_block and stream_with_block_info"` (`0x91fd5f`).
2. **`node/src/channel.rs`** (`.rodata 0x430aa0`, `Location`s `0x6451af8` L16:9, `0x6451b10` L20:33, `0x64b8c60` L16:9; FDEs `0x2e071c0..0x2e075e8` [1,064 B], `0x2e075f0..0x2e079f6` [1,030 B], `0x5a71040..0x5a7172a` [1,770 B]):
   - Biased dual-priority channel wrapper (`PriorityChannel<T>`) preferring high-priority messages before normal-priority messages.
3. **`node/src/group_and_seq_sampler.rs`** (`.rodata 0x431e32`, `Location 0x64bca88` L169:10; FDEs `0x5b298d0..0x5b2a121` [2,129 B], `0x5b2a130..0x5b2aa61` [2,353 B]):
   - Per-group/sequence elapsed-second sampler dividing nanoseconds by `1e9` (`0x458d50`) and clamping `+inf` (`0x459010` at `0x5b29977`) to `0.0`.
4. **`node/src/utils.rs`** (`.rodata 0x439d32`, `Location`s `0x6447bf0` L66:70, `0x6447c08` L66:79; FDE `0x2ae1690..0x2ae27b2`, 4,386 B):
   - Sync-to-async runtime entrypoint helper (`block_on` with nested-runtime re-entrancy guard `"Cannot start a runtime from within a runtime."` at `0x60692e`).
