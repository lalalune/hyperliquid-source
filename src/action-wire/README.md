# `action-wire` — Integrated Node #115 Action Wire & Signing Library

Target binary: Linux x86-64 `hl-node` #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

Integrates the five `action-wire` micro-crates (`node115-signed-action-four-field`,
`node115-usd-class-transfer`, `node115-action-any-reader`,
`node115-action-enum-variant-matchers`, `node115-action-msgpack-identifier`)
with independently authored Rust reconstructions of the binary-verified #115
signing, tag-mapping, replay, and error-display routines:

- `variants`: all 92 `Action` variants (`action-wire-variant-dispatch-crosswalk-115`,
  `0x36c3180`, niche `< 0x86 => VoteGlobal (20)`, tags `0x86..=0xe1`)
- `eip712`: EIP-712 signing domain (`HyperliquidSignTransaction` / `1`), selector
  tables, all 38 resolved user-signed action schemas, and Keccak-256 digest computation
  (`action-wire-signing-digest-115`, 2,673 cases, 0 mismatches)
- `error_display`: template byte decoder (`0x00`/`1..=0x7f`/`0x80+u16`/`0xc0`)
  and verified action-error tags from `0x46ef710` (`action-wire-error-display-115`,
  418 tags, 12,540 cases)
- `nonce_set`: re-exported from `l1-shared` (`0x4228080`, `0x4228310`)

## Test

```sh
CARGO_BUILD_JOBS=4 RUST_TEST_THREADS=4 \
  CARGO_TARGET_DIR=work/target/risk-exchange \
  cargo test --offline --locked --manifest-path src/action-wire/Cargo.toml
```
