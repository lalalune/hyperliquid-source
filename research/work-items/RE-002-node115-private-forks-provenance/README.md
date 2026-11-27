# RE-002: Node #115 Private Forks Provenance & Overflow-Checks Profile Evidence

- **Target**: Linux x86-64 `artifacts/node/115/hl-node`, 105,896,032 bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- **Task / Component**: `RE-002` (build provenance, private forks, and compiler profile flags); no full-component acceptance gates changed.
- **Method**: Static ELF parsing of `.rodata`, `.data.rel.ro`, `.rela.dyn`, `.eh_frame_hdr`/`.eh_frame` FDEs, and `.text` RIP-relative xrefs. No captured binary execution or emulation.

## Key Observations (ELF-verified in `records.json`)

1. **Global Rust arithmetic overflow checks (`overflow-checks = true`)**:
   - Six `.got` `R_X86_64_RELATIVE` entries resolve to `core::num::overflow_panic::{add, mul, neg_or_div, shl, shr, sub}` (`0x1681da0..0x1681e59`):
     - `0x64df520 -> 0x1681da0` (`add`)
     - `0x64df870 -> 0x1681dc0` (`mul`)
     - `0x64e00c0 -> 0x1681de0` (`neg_or_div`)
     - `0x64df840 -> 0x1681e00` (`shl`)
     - `0x64e0820 -> 0x1681e20` (`shr`)
     - `0x64df848 -> 0x1681e40` (`sub`)
   - Across node #115 `.text`, **50,151** direct/GOT `call`/`jmp` sites invoke these overflow-panic helpers across **17,453 distinct FDEs** (12.90% of all 135,313 FDEs).
   - Where an immediate `lea rdi, [rip+disp32]` (`48 8d 3d`) loads a `core::panic::Location` directly before the `call`/`jmp [rip+disp32]`, attribution spans:
     - **`z_vendor` (91 distinct vendored crates)**: 48,019 sites (led by `rmp-serde` 23,510, `serde_json` 13,205, `serde_core` 3,828, `hashbrown-0.15.2` 2,838, `serde` 1,173, `rayon-core` 340, `crossbeam-deque` 322, `bytes` 265, `ruint` 228, `rayon` 214, `k256` 147, `h2` 131, `alloy-consensus` 119, `indexmap` 108, `revm-interpreter` 104, `itoa` 100, `tokio` 99, `chrono` 93, `revm-context-interface` 88, `curve25519-dalek-ng` 80, `http-0.2.12` 68, `rust_decimal` 65, `keccak-asm` 55, `hashbrown-0.16.1` 52, `alloy-rlp` 50).
     - **`rustc_std`**: 657 sites.
     - **First-party crates**: 264 sites (`l1` 259, `base` 3, `node` 2).
     - **`z_forks` (4 of 8 private forks)**: 253 sites (`bincode-fork` 124, `hyper-fork` 105, `revm-precompile` 20, `reth-rpc-eth-types` 4).

2. **All 8 private forks (`z_forks/<fork>/...`) `Location` & FDE map**:

| Private fork | Raw path hits | Source files | `Location` structs | Unique `file:line:col` | Referencing FDEs | Immediate overflow-panic sites |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `bincode-fork` | 4 | 4 | 13 | 4 | 100 | 124 |
| `hyper-fork` | 200 | 25 | 651 | 274 | 247 | 105 |
| `hyper-tls-fork` | 1 | 1 | 6 | 2 | 6 | 0 |
| `reth-chainspec` | 1 | 1 | 2 | 2 | 1 | 0 |
| `reth-ethereum-forks` | 1 | 1 | 1 | 1 | 1 | 0 |
| `reth-rpc-eth-types` | 2 | 2 | 4 | 4 | 3 | 4 |
| `reth-rpc-server-types` | 1 | 1 | 1 | 1 | 1 | 0 |
| `revm-precompile` | 12 | 12 | 34 | 34 | 23 | 20 |

## Inferences (Strictly Separated from Binary Observations)

Comparing the exact ELF-observed `(file, line, col)` tuples against published upstream releases establishes the upstream base and localized line-shift footprints of all 8 forks:

1. **`bincode-fork`** — **Base: `bincode 2.0.0` / `2.0.1`** (correcting earlier `gcc-forkbases` assumption of `bincode 1.3.3`):
   - `src/de/decoder.rs:93:13` (`self.bytes_read -= n;`), `src/de/impls.rs:499:20` (`result.unwrap()`), and `src/enc/write.rs:78:9` (`self.bytes_written += bytes.len();`) match `bincode 2.0.0`/`2.0.1` verbatim in both line and column.
   - `src/lib.rs:171:22` matches `src.len() - decoder.reader().slice.len()` at column 22 with a **+1 line shift** from upstream line 170.
2. **`hyper-fork`** — **Base: `hyper 0.14.16`** (distinct from `z_vendor/hyper` `0.14.32` used by `axum` server):
   - 199/274 unique `file:line:col` entries match `hyper 0.14.16` verbatim (vs 156 for `0.14.17`, 124 for `0.14.15`, and 59 for `0.14.32`), including 31/31 in `src/proto/h1/conn.rs`, 13/13 in `src/proto/h1/dispatch.rs`, 14/14 in `src/proto/h1/encode.rs`, and 26/27 in `src/client/pool.rs`.
   - Localized client modifications: `src/client/client.rs` shifted **+1 line** across 19/22 locations; `src/client/connect/http.rs` shifted **+10** by line 280, **+11** by line 364, and **+42** across lines 576..712 (+31 lines inserted between `set_nodelay` and `ConnectingTcpRemote::connect`, preserving `tcp set_keepalive/reuse_address/buffer_size/recv_buffer_size` warnings at lines 648/681/687/693).
3. **`hyper-tls-fork`** — **Base: `hyper-tls 0.5.0`**:
   - `src/client.rs:127:19` and `src/client.rs:142:30` match `hyper-tls 0.5.0` lines 135 and 150 (constant **-8 line shift**), paired with `hyper-fork`.
4. **`reth-chainspec`** — **Base: `reth >= v2.1.0` (`v2.3.0` / `v2.4.1` era matching `revm 40.0.3`)**:
   - FDE `0x5bccf90..0x5bcd9e5` embeds `"ParisCancunPragueOsakaAmsterdam"` (`Amsterdam` was introduced in `reth v2.1.0`) and matches `ChainSpecBuilder::build` expect columns verbatim (`1220:36` vs upstream `1234:36`, `1222:31` vs upstream `1236:31`; **-14 line shift**).
5. **`reth-ethereum-forks`** — **Base: `reth v2.3.0` / `v2.4.1`**:
   - `src/hardforks/mod.rs:150:20` matches `self.forks.insert(pos, (Box::new(fork), condition));` verbatim (0-line shift).
6. **`reth-rpc-eth-types`** — **Base: `reth v2.3.0` / `v2.4.1`**:
   - `src/utils.rs:19:13` (`next_log_index += receipt.logs().len();`) matches verbatim (0-line shift).
   - `src/fee_history.rs:34:28`, `68:13`, `70:43` match `calculate_reward_percentiles_for_block` columns verbatim (`304:28`, `333:13`, `334:43`), showing **~270 lines of async `FeeHistoryCache` were stripped** from the top of `src/fee_history.rs` (plus +5 lines inside the percentile function).
7. **`reth-rpc-server-types`** — **Base: `reth v2.3.0` / `v2.4.1`**:
   - FDE `0x5bda990..0x5bdaabd` references `"serializing String can't fail"` at `src/result.rs:143:18`, matching upstream `150:18` (**-7 line shift**, exact column).
8. **`revm-precompile`** — **Base: `revm-precompile 36.0.0` / `36.0.1` (`revm 40.0.3` era)**:
   - **34/34 (100%)** observed `file:line:col` locations across all 12 files match `revm-precompile 36.0.0`/`36.0.1` verbatim in both line and column.
9. **Build profile impact**:
   - Enabling `overflow-checks = true` in `[profile.release]` explains why default-release (`overflow-checks = false`) dependency builds failed to match arithmetic-bearing functions in `z_vendor/*`, `z_forks/reth-*`, `z_forks/revm-precompile`, and first-party crates.

## Verification

```sh
python3 research/work-items/RE-002-node115-private-forks-provenance/verify.py
python3 -m unittest tests/test_private_forks_provenance_115.py
```

## Unknowns and Limitations

- Only source files with surviving `Location` or path strings in `.rodata`/`.data.rel.ro` appear in this static map; panic-free or fully inlined fork files require function-level byte/CFG comparison against `overflow-checks = true` builds.
- Exact upstream git commit hashes for the four `reth-*` forks and exact body diffs of the +31 inserted lines in `hyper-fork/src/client/connect/http.rs` remain to be recovered by function-level comparison.
- This packet establishes build-profile and fork provenance only; no component acceptance gate is marked true.
