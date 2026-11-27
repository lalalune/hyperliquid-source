# RE-009: node #115 ABCI state-root digest is standard unkeyed BLAKE3

- Component ID: `abci` / `storage`
- Target release and full SHA-256: Linux x86-64 node #115, `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (105,896,032 bytes)
- Closes the open digest-algorithm question from `RE-017-abci-root-tree-115`, `RE-009-node115-root-digest-selector`, and `RE-009-node115-root-digest-cell-writer`.

## Binary findings

1. `0x548dad0` (`l1/src/abci/abci_hash.rs:28`) calls outer digest entry `0x41c5140` via `R_X86_64_RELATIVE` slot `0x64e7820`.
2. `0x41c5140` initializes a standard unkeyed **BLAKE3** `Hasher` using the exact 8-word BLAKE3 IV at `.rodata 0x457ae0..0x457b00`:
   `[0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]`, with initial flags `0`, chunk length `0`, and platform byte returned by `0x160bee0` (`blake3::platform::Platform::detect()`).
3. `0x41c5387` calls `0x160b3a0` (`blake3::Hasher::update`) with 1024-byte chunking (`0x400` at `0x160b3dc`) and `CHUNK_END = 2` (`0x160b412`).
4. `0x41c539a` calls `0x160bcd0` (`blake3::Hasher::finalize`), ORing `ROOT = 8` (`0x160bd08`) and dispatching through the 5-arm `.rodata` jump table `0x46ab4c` to the 4 `compress_in_place` implementations:
   - Arm 0 (portable): `0x160bd54 -> slot 0x64e1960 -> 0x160d200`
   - Arm 1 (SSE2): `0x160bd6d -> slot 0x64e1968 -> 0x633d0c0`
   - Arms 2 & 3 (SSE4.1 / AVX2): `0x160bd22 -> slot 0x64e1950 -> 0x633fac0`
   - Arm 4 (AVX-512): `0x160bd3b -> slot 0x64e1958 -> 0x6345bc0`

## Implementation

`src/node115-abci-blake3` provides a zero-dependency, `#![forbid(unsafe_code)]`, `no_std + alloc` standard BLAKE3 implementation verified against official BLAKE3 specification test vectors (0 B through 102,400 B across chunk boundaries and Merkle tree parent chaining), together with node #115's state-root reduction-tree MessagePack preimage encoder (`compute_reduction_tree_root`, `compute_leaf_root`).

## Reproduce

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-009-node115-abci-blake3-root/verify.py --self-test
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_abci_blake3_root_115
(cd research/work-items/RE-009-node115-abci-blake3-root && sha256sum -c MANIFEST.sha256)
CARGO_BUILD_JOBS=4 RUST_TEST_THREADS=4 CARGO_TARGET_DIR=work/target/storage-abci \
  cargo test --offline --locked --manifest-path src/node115-abci-blake3/Cargo.toml
```
