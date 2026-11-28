# RE-009: Model a leaf at the root of the #115 ABCI reduction tree

The existing Rust root helper takes a vector of reduction rows, which
models the nested-root branch. The
[authenticated #115 tree serializer](../RE-008-abci-hash-tree-encoding-115/README.md)
also has a selected top-level leaf branch. It writes the whole 32-byte
leaf digest as one MessagePack string before BLAKE3. A leaf value already
being 32 bytes does not make it the raw ABCI digest.

The new entry point takes the existing `ReductionNode`. It reuses the
nested reduction and the existing fixed leaf encoder. The offline tests
check a fixed string containing leading zeros and high bytes. The
expected result was computed independently with BLAKE3 1.0.8. A
separate test verifies that a typed nested node gives the existing row
API's result.

The input is already a reconstructed tree. This does not derive its leaves
from restored state, authenticate a live root or calculate replay by itself.

```sh
python3 -B research/work-items/RE-009-node115-abci-typed-root-node/verify.py
cargo test --locked --offline --manifest-path src/node115-abci/Cargo.toml
```

[Raw offline log](offline-log.txt)
