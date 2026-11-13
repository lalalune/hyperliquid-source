# node115-token-id

Independent Rust model of how node #115 turns a `TokenSpec` and a token index into the 16-byte token id,
plus the two gates around it in the registration caller (index limit, duplicate id). Scope, evidence and
every limitation are in the packet
[`RE-005-node115-token-id-derivation`](../../research/work-items/RE-005-node115-token-id-derivation/README.md);
this file only says how to use and test the crate.

```rust
use node115_token_id::{token_id, TokenIds, TokenSpec};
let spec = TokenSpec { name: "X", sz_decimals: 6, wei_decimals: 8 };
assert_eq!(hex(token_id(&spec, 0)?), "9058f4586f457c793b70c2871d15c2d5"); // preimage: 9283a46e...0800
let mut ids = TokenIds::new();
ids.register(&spec, 0)?;            // Err(TokenIdAlreadyExists) the second time, Err(TooManyTokens) above 99,998
```

* `preimage` / `digest` / `token_id`: the bytes `0x38d2ce0` hashes, its 32-byte result, and the first 16 bytes
  the caller keeps. Total over every `u64` index and every name shorter than 2^32 bytes.
* `Keccak256`: incremental absorb/finalize with the observed state record (rate 136, delimiter `0x01`),
  on top of the existing [`node115-sponge-permutation`](../node115-sponge-permutation/README.md) through a
  path dependency (`permutation-adapter/`, the same pattern as `node115-noop-preimage`). No crates.io
  dependencies, no workspace.
* `TokenIds::register`: index limit, id derivation, membership test, insert: the two selected checks of the
  caller tail and the order between them. Only the logical set is modelled, not the native two-form container.
  It is not the registration: the caller rejects earlier (for a nonzero index, `szDecimals > 5` or
  `weiDecimals < szDecimals + 5`, among others), and those gates are not modelled.

Not covered: the other gates of the registration function, token records, native allocation and unwind
behaviour, names of 2^32 bytes or more (`Error::NameTooLong`).

Tests (9: one unit test, eight integration tests over the frozen corpus of the packet) are **not** run by
`make test`, which only collects the Python files under `tests/`. The registry tests are named
`selected_check_*` because they cover only the two selected checks, with inputs that pass the caller's
decimals check. Run them by hand:

```sh
cargo test --offline --locked --manifest-path src/node115-token-id/Cargo.toml --target-dir work/token-id-target
```

Built and tested with cargo/rustc 1.99.1; the repository pins 1.95.0, which was not available.
New source is MIT; the permutation crate keeps its own header and licence.
