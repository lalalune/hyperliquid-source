# Node115 display-name decision

An independently authored, allocation-free `no_std` projection of the selected
`setDisplayName` branch order at node115 `0x2392200` and `0x2c76380`.

The API accepts the already-evaluated prior-key-rejection and duplicate-value
predicates plus the display-name length. It returns the selected path, outer
tag, result word and logical mutation category. It does not decode JSON,
compare account keys, own strings, perform erase/upsert storage operations or
serialize a response.

See the evidence packet at
[`research/work-items/RE-010-node115-display-name-decision`](../../research/work-items/RE-010-node115-display-name-decision/README.md).

```sh
cargo test --offline --locked
cargo test --offline --locked --release
cargo fmt --all --check
cargo clippy --offline --locked --all-targets -- -D warnings
cargo build --offline --locked --release --lib
```
