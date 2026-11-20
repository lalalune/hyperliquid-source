# Bulk construction of the startup path tree

Both directory collectors pass their sorted array of owned UTF-8 paths to `0x1539de0`. This change adds `src/node115-bulk-path-tree`, an independently authored Rust reconstruction of that bulk builder, its duplicate policy, right-edge growth, and final redistribution. It accepts the sorter's output and exposes ordered traversal and the rightmost path. The prior [discovery ordering packet](../RE-017-node115-replica-discovery-order/README.md) and [startup sorting PR](https://github.com/lalalune/hyperliquid-source/pull/7052) document the input pipeline.

Target `artifacts/node/115/hl-node` is 105896032 bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Coordinates are image VAs.

## Native behavior

* Empty listings return directly from `0x15b58c0` / `0x15b59e0`. Nonempty listings call `0x1539de0`, which allocates an empty leaf, gives the builder a root/height pair and a separate key count, then publishes all three.
* Starting at `0x149bc70` the builder looks ahead one 24-byte path descriptor. Equal byte lengths lead to `bcmp` at `0x149bcbf`. On equality, it disposes of the previous allocation and keeps the next descriptor pending. The last allocation of each equal run survives. Distinct keys append in their supplied order.
* A node holds eleven keys. On a full leaf, `0x149bd20` climbs the right spine to find a parent with room. If necessary it installs a new root above the old root. The incoming key goes into that parent, with an initially empty right branch descending to the old leaf depth. The root's height increases only when the old root was full along this entire route.
* At the end `0x149bfe8..0x149c052` descends the right spine. If the right child has fewer than five keys, it calls `0x1498950` with exactly the deficit. The helper shifts right-side records, promotes a left sibling key to the parent, moves the old separator down and transfers the corresponding child edges. The Rust uses ownership to preserve these relationships.
* Startup's directory selector at `0x595b590..0x595b69c` follows each node's rightmost child and obtains the last leaf entry. The returned path bytes and tree order are observable without reading a process or accessing a filesystem.

The source checks its sorted-input precondition. The supported interface uses valid UTF-8 strings. Host allocations, native pointer values, parent back-pointers and allocation failure paths are outside the reconstruction.

## Verification

```sh
python3 research/work-items/RE-012-node115-bulk-path-tree/verify.py --target artifacts/node/115/hl-node
cargo test --offline --manifest-path src/node115-bulk-path-tree/Cargo.toml
```

Capstone 5.0.7 and pyelftools verify the pinned ELF, FDEs, transfers and comparison imports. Manually specified expected root separators and child occupancies cover 12, 13, 17, 23 and 24 keys. Tests also exercise both sides of the two- and three-level boundaries, up to 4,097 keys. They check every node's occupancy and every key's position, compare the last key with an independently generated ordered sequence, and verify that a separately allocated equal path survives by its pointer identity. All checks run offline.
