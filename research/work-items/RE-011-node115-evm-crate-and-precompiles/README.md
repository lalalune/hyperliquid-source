# RE-011: node #115 HyperEVM read precompile gas schedule (`0x0800..0x0814`) and `evm` crate integration

This packet closes the exact gas formula across all 21 HyperEVM read precompile callbacks (`0x0800..=0x0814`), records all fixed output lengths directly from their post-output gas immediates, maps all 9 `l1/src/evm/{evm_db,evm_state,hash,hyper_evm}.rs` panic `Location` records and all 12 `z_forks/revm-precompile` source paths, and integrates all six verified node #115 EVM micro-crates into `src/evm/`.

- Component ID: `evm` (`l1/evm/*`, `revm-precompile`); task `RE-011`.
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (`artifacts/node/115/hl-node`).
- Claim status:
  - **Observation**: ELF section bounds, all 21 read precompile records (`0x646e4e0..0x646e778`) and callback FDE body SHA-256s (`0x38df640..0x38e93e0`), shared preamble `cmp rcx, 0x7d0` (`2000`) + `33 * input_len + 1000` across 21/21 callbacks, post-output gas immediates (`2056/3112/4168/5224/6280` = `1000 + 33 * {32,64,96,128,160}`) for all 14 fixed-width callbacks, `0x0809` (`0x38e3b40`) `bswap` + 32-byte big-endian word output, all 9 `l1/src/evm/*` `R_X86_64_RELATIVE` panic `Location` records, and all 12 `z_forks/revm-precompile/src/*.rs` `.rodata` paths.
  - **Inference**: Domain names (`L1BlockNumber`, `EvmDbKeyspace`, `LtHash`, `Mode13GasInput`) and Rust module decomposition.
  - **Unresolved**: Full L1-state read queries inside the other 20 read precompile callbacks (`0x0800..0x0808`, `0x080a..0x0814`), complete `revm` opcode interpreter loop, dual-block mempool scheduling inside `hyper_evm.rs`, and whole-crate `rustc 1.95.0` codegen identity.
- Captured code executed: `false`. Static binary analysis + independently authored MIT Rust tests only.
- Progress gate: no automatic gate flip claimed in this packet.

## Key node #115 observations

1. **Universal Read Precompile Gas Formula (`21/21` callbacks `0x0800..=0x0814`)**:
   - Input length limit: `input.len() <= 2000` (`0x7d0`), else `OutOfGas` (`[rdi]=0, [rdi+8]=0x8000000000000001`).
   - Phase-1 preflight gas: `1000 + 33 * input.len()` (`(len << 5) + len + 0x3e8`), else `OutOfGas`.
   - Phase-2 total gas: `1000 + 33 * (input.len() + output.len())`, verified by exact immediates in all 14 fixed-width callbacks:
     - `32B` (`+0x808 = 2056`): `0x0803`, `0x0806`, `0x0807`, `0x0808`, `0x0809`, `0x0810`
     - `64B` (`+0xc28 = 3112`): `0x0802`, `0x080e`
     - `96B` (`+0x1048 = 4168`): `0x0801`, `0x0814`
     - `128B` (`+0x1468 = 5224`): `0x0805`, `0x080f`
     - `160B` (`+0x1888 = 6280`): `0x0800`, `0x0813`
     - Dynamic output (7 callbacks): `0x0804`, `0x080a`, `0x080b`, `0x080c`, `0x080d`, `0x0811`, `0x0812`.
2. **All 9 `l1/src/evm/*` panic `Location` records**:
   - `evm_db.rs`: `91:14` (`0x646ec68`), `94:14` (`0x646ec80`), `189:67` (`0x646e818`)
   - `evm_state.rs`: `183:9` (`0x648be28`)
   - `hash.rs`: `68:27` (`0x646e800`)
   - `hyper_evm.rs`: `120:17` (`0x6443cc0`, `0x64aa1f0`), `182:62` (`0x6443ca8`, `0x64aa1d8`).
3. **Integrated `src/evm/` crate**: joins all 6 verified EVM micro-crates (`node115-evm-precompile-outcome-names`, `node115-evm-tx-type-names`, `node115-read-precompile-result`, `node115-child-reserve-fold`, `node115-sstore-warm`, `node115-transient-rollback-branches`) + `node115-token-id` (`keccak256`) with `precompiles`, `gas`, and `lt_hash`.

## Reproduce

```sh
CARGO_BUILD_JOBS=4 RUST_TEST_THREADS=4 CARGO_TARGET_DIR=work/target/evm-bridge-api \
  cargo test --offline --locked --manifest-path src/evm/Cargo.toml
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_evm_crate_115 -v
```
