# RE-002: Node #115 Private-Fork Patch Analysis & Deterministic Linux Build Plan

- **Component / Task**: `RE-002` (build provenance, private-fork diff closure, and deterministic Linux x86-64 build plan); no component acceptance gate requested.
- **Target**: Linux x86-64 `artifacts/node/115/hl-node`, 105,896,032 bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- **Method**: Static ELF `.rodata` + `.text` instruction verification against `artifacts/node/115/hl-node` and line/column comparison against upstream bases cached during `RE-002-node115-private-forks-provenance`. No captured binary execution.

## Binary-Verified Custom Patch Findings (`hyper-fork` + all 8 `z_forks/*`)

1. **`hyper-fork` (`hyper 0.14.16` base) — exact purpose of the `+31` inserted lines in `src/client/connect/http.rs`**:
   - **Patch Anchor #1 (`http.rs:494:21`, FDE `0x2e7c100..0x2e7d609`)**: At `0x2e7d444`, `.text` loads `.rodata` `0x44be0e` (`\x12two matching urls \xc0\x01 \xc0\x01 \xc0\x00`, Rust 1.95.0 compressed `fmt::Arguments` template for `panic!("two matching urls {} {} {}", ...)`) together with `Location` `0x645a110` (`z_forks/hyper-fork/src/client/connect/http.rs:494:21`). This enforces unique per-URL address-override matching inside `ConnectingTcp::new`.
   - **Patch Anchor #2 (`http.rs:558:85`, 4 monomorphized FDEs `0x15aeae0..0x15af9cc`, `0x16f6f90..0x16f7eb6`, `0x17457f0..0x17480df`, `0x2b11c60..0x2b12b4c`)**: At `0x15aec8f`, `.text` loads `.rodata` `0x44e4d0` (`\x17hyper-fork only trying \xc0\x04 on \xc0\x01\n\x00`, `"hyper-fork only trying {} on {}\n"`), prints it, allocates a 32-byte (`0x20`) buffer (`0x15aeca4`), copies a single 32-byte `SocketAddr` (`0x15aecb4..0x15aeccb`), and sets `len = 1` (`r13d = 1`) and `cap = 1` (`ecx = 1`) to replace the resolved DNS `SocketAddrs` vector so `ConnectingTcpRemote::connect` attempts only that selected `SocketAddr`.
2. **`hyper-tls-fork` (`hyper-tls 0.5.0` base)**:
   - Re-points `hyper-tls` to `hyper-fork` with a constant `-8` line shift in `src/client.rs` (`127:19`, `142:30` vs upstream `135`, `150`).
3. **`bincode-fork` (`bincode 2.0.0 / 2.0.1` base)**:
   - `+1` line in `src/lib.rs` (`171:22` vs `170:22`), `0`-line shift in `de/decoder.rs`, `de/impls.rs`, `enc/write.rs`, plus bounded-length/wire guard (`InvalidBytesLength`, independently reconstructed in `src/bincode-fork`).
4. **Reth & Revm forks (`reth v2.3.0 / v2.4.1` & `revm-precompile 36.0.0 / 36.0.1` era)**:
   - `reth-chainspec`: retains `"ParisCancunPragueOsakaAmsterdam"` (`0x45a5af`, FDE `0x5bccf90..0x5bcd9e5`), `-14` lines in `src/spec.rs`.
   - `reth-ethereum-forks`: `0`-line shift at `src/hardforks/mod.rs:150:20` (`0x5bd51a0..0x5bd5668`).
   - `reth-rpc-eth-types`: strips ~270 lines of async `FeeHistoryCache` from `src/fee_history.rs`, retaining synchronous `calculate_reward_percentiles_for_block` (`0x2a1fd20..0x2a21c6d`).
   - `reth-rpc-server-types`: retains `"serializing String can't fail"` (`0x9418a3`, FDE `0x5bda990..0x5bdaabd`), `-7` lines in `src/result.rs`.
   - `revm-precompile`: `34/34` (`100%`) exact line:col match to `36.0.0` / `36.0.1`.

## Deterministic Linux x86-64 Build Plan (`RE-002` Deliverable)

- **Rust toolchain (`.comment` verified)**: `rustc 1.95.0 (59807616e 2026-04-14)`, `LLD 22.1.2`, target `x86_64-unknown-linux-gnu` (pinned in `rust-toolchain.toml`).
- **Native C/C++ compiler (`.comment` verified)**: Ubuntu 24.04 `GCC 13.3.0-6ubuntu2~24.04.1` for `-sys` crates (`rocksdb`, `secp256k1-sys`, `blst`, `tikv-jemalloc-sys`).
- **Verified `[profile.release]` flags**:
  - `opt-level = 3`
  - `overflow-checks = true` (proven by 50,151 `overflow_panic::*` call/jmp sites across 17,453 FDEs in `RE-002-node115-private-forks-provenance`, and validated by 92 first-party byte-census matches under `rustc 1.95.0 -C opt-level=3 -C overflow-checks=yes`)
  - `codegen-units = 16`
  - `lto = false`
  - `panic = "unwind"`
- **Offline source workspace & container delivery**:
  - `src/hl-node/Cargo.toml` + `src/hl-node/Cargo.lock` (offline, zero external deps, `[profile.release] overflow-checks = true`)
  - `src/hl-node/Dockerfile` (pinned Linux/amd64 `rust:1.95.0-bookworm` -> `ubuntu:24.04` unprivileged `hluser`)

## Remaining Unknowns & Limitations

- Exact upstream git commit SHAs of the four `reth-*` fork snapshots within the `v2.3.0..v2.4.1` era remain unpinned by `.rodata` alone.
- Fork files or branches that contain neither panics nor string literals do not leave `.rodata`/`.data.rel.ro` footprints and require function-level byte comparison.
- Exact Rust identifier name of the URL-override map field inside `hyper-fork`'s `Config` struct is not emitted in stripped symbols.
- No component gate in `research/progress.json` is flipped by this packet.

## Verification

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-002-node115-private-forks-patch-analysis/verify.py
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_private_forks_patch_analysis_115 -v
(cd research/work-items/RE-002-node115-private-forks-patch-analysis && sha256sum -c MANIFEST.sha256)
```
