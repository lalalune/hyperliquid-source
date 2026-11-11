# node115-bridge-preimage

Reconstructs the selected bridge builder's complete 64-byte `zero12 || input20 || input32` preimage and bounded inner digest. Inputs are opaque fields already produced by the native caller; this crate performs no request decoding, authorization or signing.

The unchanged MIT permutation is reused through a local adapter. See [the evidence packet](../../research/work-items/RE-005-node115-bridge-preimage/README.md) for the real append/flatten/digest call chain, reference vectors and limits.

```sh
cargo +1.95.0 test --offline --locked --manifest-path src/node115-bridge-preimage/Cargo.toml
```
