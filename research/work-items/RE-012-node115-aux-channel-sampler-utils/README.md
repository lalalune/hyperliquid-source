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
   - Per-group/sequence elapsed-second sampler dividing the subsecond remainder by `1e9` before adding whole seconds (`0x458d50`) and clamping `+inf` (`0x459010` at `0x5b29977`) to `0.0`.
4. **`node/src/utils.rs`** (`.rodata 0x439d32`, `Location`s `0x6447bf0` L66:70, `0x6447c08` L66:79; FDE `0x2ae1690..0x2ae27b2`, 4,386 B):
   - Sync-to-async runtime entrypoint helper (`block_on` with nested-runtime re-entrancy guard `"Cannot start a runtime from within a runtime."` at `0x60692e`).

## Group latency measurements

Both sampler specializations call the two-input [timespec difference](../RE-012-timespec-difference-115/README.md).
The 94 bytes at each call site determine the duration passed on to the sampler. The table gives virtual addresses in the authenticated image.

| Operation | First specialization | Second specialization |
|---|---|---|
| Call difference at `0x5c84210` | `0x5b2992d` | `0x5b2a18e` |
| Test direction marker, initialize zero, skip the conversion on reverse order | `0x5b29932` | `0x5b2a193` |
| Read whole seconds and subsecond nanos | `0x5b29941` | `0x5b2a1a2` |
| Convert unsigned seconds to binary64 using two 32-bit lanes | `0x5b29950` | `0x5b2a1b1` |
| Divide nanos by one billion, then add the converted whole seconds | `0x5b2996b` | `0x5b2a1cc` |
| Compare with the infinity constant, then store the selected result | `0x5b29977` | `0x5b2a1d8` |

For 1.118 seconds the two-stage calculation yields binary64 bits `0x3ff1e353f7ced916`.
The previous public `GroupAndSeqSampler::record_nanos` cast the total nanoseconds to a float
and divided once, producing `0x3ff1e353f7ced917`. Recording that sample twice also changes
the last bit of the group's reported total. The integrated method now uses
[`Duration::as_secs_f64` in Rust 1.95.0](https://github.com/rust-lang/rust/blob/1.95.0/library/core/src/time.rs#L866-L868),
which performs the two operations in the observed order.

The comparison calls the compiled `node-runtime` public API for every millisecond from zero
through 60.999 seconds, values next to powers of two and the top of the `u64` nanoseconds
range. A separate rational-arithmetic reference rounds each floating operation. The base
and fixed results cover the same 61,404 measurements in 161 groups.

| Recorded field | Base differences | Fixed differences |
|---|---:|---:|
| Individual elapsed time | 792 | 0 |
| Group count | 0 | 0 |
| Running group total | 200 | 0 |
| Running group maximum | 792 | 0 |

The per-group count, total and maximum are outputs of this crate's aggregation API. The
binary evidence covers each elapsed input. The target was inspected statically. Ring
collection and reporting gates are covered by the [earlier sampler packet](../RE-001-node115-group-sampler-gates/README.md).

From the repository root, with Python 3.10+, Cargo/Rust 1.95 and the pinned node artifact:

```sh
packet=research/work-items/RE-012-node115-aux-channel-sampler-utils
python3 -B "$packet/compare_elapsed.py" --expect fixed
baseline=$(mktemp -d)
git archive 2da45cb0a761cff6b478e40421699857d87a94df src | tar -x -C "$baseline"
python3 -B "$packet/compare_elapsed.py" --source-root "$baseline" --expect base
cargo test --manifest-path src/node-runtime/Cargo.toml --locked --offline --test aux_and_samplers
```

The comparison verifies the two instruction windows, their data references and the artifact digest.
It builds an offline Rust probe against the selected source tree and checks the results and input/output
hashes against [the retained observations](elapsed-results.json). Only the compiled project and probe run.
