# Node115 DB-hub byte-key lookup

An independently authored, allocation-free `no_std` projection of the selected
node115 DB-hub byte-key traversal at `0x1692ca0..0x1692fe9`.

The model accepts only the low byte of the query word, scans each node's sorted
keys to the first key greater than or equal to the query, follows the matching
child on a miss, and permits a zero-height root match without further descent.

This is not the original tree ABI, storage representation, database operation or
DB-hub API. It assumes the tree-shape and ordering invariants enforced by
`Node::new`; malformed native layouts, cycles, allocation, persistence,
concurrency and database I/O remain outside the relation.

See the evidence packet at
[`research/work-items/RE-009-node115-db-hub-byte-key-lookup`](../../research/work-items/RE-009-node115-db-hub-byte-key-lookup/README.md).

```sh
cargo test --offline --locked
cargo test --offline --locked --release
cargo fmt --all --check
cargo clippy --offline --locked --all-targets -- -D warnings
cargo build --offline --locked --release --lib
```
