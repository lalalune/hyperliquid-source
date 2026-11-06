# Node #115 staking error texts

Independent `no_std` table of thirteen static staking, delegation, jailing and
commission strings, plus the two format templates and the binary64 bits
`0x4072c00000000000` (exactly 300.0) from the node #115 action-error display
at `0x46ef710`.

The native formatter ABI, float printer, jailed-until payload, comparison that
raises these errors, and the other 403 display arms are not implemented.
Evidence is in
[RE-001-node115-staking-error-display](../../research/work-items/RE-001-node115-staking-error-display/README.md).

```sh
cargo test --locked --offline --manifest-path src/node115-staking-error-text/Cargo.toml
```
