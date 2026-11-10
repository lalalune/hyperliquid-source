# node115-vault-address

Independent Rust model of how node #115 names a new vault: the 20-byte address derived from the creator and the
`createVault` request, plus the two checks the analysed caller makes around that derivation. Scope, evidence and
every limitation are in the packet
[`RE-005-node115-vault-address-derivation`](../../research/work-items/RE-005-node115-vault-address-derivation/README.md);
this file only says how to use and test the crate.

This is a static reconstruction: the binary was never executed or emulated and no behavioural equivalence with the node
is claimed. **`caller_address` returning `Ok` only means that the name-length and amount checks of the analysed caller
passed; it does not mean a vault was created.** The role names (`creator`, the request fields, "vault address") are
inferences from key literals, offsets and position, not recovered meanings; what the 20 creator bytes are upstream
(the action's signing user?) was not traced.

```rust
use node115_vault_address::{derive_vault_address, caller_address, CreateVaultRequest};
let request = CreateVaultRequest { max_usdc_fee: None, name: "v".into(), description: String::new(), initial_usd: 1, nonce: 2 };
let address = derive_vault_address(&[0; 20], &request)?;   // 91378d2649be144c8abfa4d4b7626d5413ceb45e
let accepted = caller_address(&[0; 20], &request);          // Ok(same address); Err(NameTooLong) from 101 bytes, Err(AmountTooLarge) from 0x0ccccccccccccccc
```

* `address_preimage` / `address_digest` / `derive_vault_address`: the bytes `0x38d2ef0` hashes, its 32-byte result and
  the first 20 bytes the entry function `0x46dba10` returns. `max_usdc_fee` is never read. Defined for requests whose
  strings are shorter than 2^32 bytes (allocation failure and unwind are not modelled); it does **not** apply the
  caller's limits.
* `caller_address`: the same derivation behind the analysed caller's name limit (before) and amount bounds
  (after). `Ok(address)` = "passed these two checks", not "vault created". It stops where the caller hands the address
  on; what the caller does next (containers probed, the creation call) is not modelled.
* `Keccak256`: incremental absorb/finalize with the observed state record (rate 136, delimiter `0x01`), on top of the
  existing [`node115-sponge-permutation`](../node115-sponge-permutation/README.md) through a path dependency
  (`permutation-adapter/`, the same pattern as `node115-noop-preimage`). No crates.io dependencies, no workspace.

Not covered: creating a vault or any state change, allocation failure and unwind, the native result record layout,
strings of 2^32 bytes or more (`Error::StringTooLong`), the caller's state gate and its remaining checks.

Tests (10: one unit test, nine integration tests over the frozen corpus and the pins of the packet) are **not** run by
`make test`, which only collects the Python files under `tests/`. They compare the crate with fixed expected values
(the frozen oracle), not with a running node. Run them by hand:

```sh
cargo test --offline --locked --manifest-path src/node115-vault-address/Cargo.toml --target-dir work/vault-address-target
```

Built and tested with cargo/rustc 1.99.1; the repository pins 1.95.0, which was not available.
New source is MIT; the permutation crate keeps its own header and licence.
