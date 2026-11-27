# `vaults` — Integrated Node #115 Vaults & Sub-Accounts Library

Target binary: Linux x86-64 `hl-node` #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

This crate integrates the five existing node #115 vault micro-crates with the
independently authored Rust reconstructions of the binary-verified vault and
sub-account routines from:

- `src/node115-vault-address` (`0x46dba10`, `0x2bdd3b0`)
- `src/node115-vault-create-context` (`0x2bdd3b0 -> 0x44ae810`)
- `src/node115-vault-identity-guards` (`0x44ae810` entry prelude)
- `src/node115-vault-redistribution` & `src/node115-vault-weight-update` (`0x44ad9e0`)
- `research/work-items/vaults-amount-helper-115` (`0x44a9430`)
- `research/work-items/vaults-base-conversion-115` (`0x3beb980`)
- `research/work-items/vaults-move-core-115` (`0x44ae810`, `0x14ca350`, `0x421a3c0`, `0x421a520`)
- `research/work-items/vaults-withdraw-gate-115` (`0x44ab4a0`)
- `research/work-items/vaults-split-body-115` (`0x44af2f0`)
- `research/work-items/RE-001-node115-subaccount-admission-append` (`0x366a620`, `l1/src/sub_account.rs:75`)
- `research/work-items/RE-012-subaccount-label-guard-115` (`0x366b350`)

## Scope and limitations

- Pure standard-library Rust (`#![forbid(unsafe_code)]`), no external dependencies.
- Reconstructs established static and byte-executed semantics only; does not
  claim full-node binary identity or component gate completion.
- Native allocator failure, unwind paths, and external clearinghouse state
  mutations behind indirect slots remain modeled as explicit typed interfaces.

## Test

```sh
CARGO_BUILD_JOBS=4 RUST_TEST_THREADS=4 \
  CARGO_TARGET_DIR=work/target/risk-exchange \
  cargo test --manifest-path src/vaults/Cargo.toml
```
