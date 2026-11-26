# Node #115 selected bridge request ABI shape

This crate independently encodes the statically reconstructed tag-5 `requestWithdrawal` tuple as a 224-byte value. It models two 20-byte inputs, two 64-bit inputs, and the 17-byte literal label. The public names of the four input fields are not established by this crate. It does not sign, hash, call the node, or claim runtime equivalence.

The accepted binary evidence and unresolved assumptions are recorded in [RE-005-node115-bridge-request-abi-layout](../../research/work-items/RE-005-node115-bridge-request-abi-layout/README.md).

```sh
cargo test --offline --manifest-path src/node115-bridge-request-abi/Cargo.toml
```
