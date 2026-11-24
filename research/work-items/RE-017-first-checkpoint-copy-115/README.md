# First historical EvmState copy in local restore

An offline restore caller can take the path returned by exact-height selection, create the live DB home if needed, and prepare the first copy that uses the historical directory. The Rust implementation lives under [restore-copy](../../../src/node115-owned-db-open/restore-copy). It accepts the two resolved paths and returns an inspectable command. The target is Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Base revision `8f8a38d0d44f0c41a94aa156bb4274777f20fd4d`.

## From the selected row to both command operands

The [local reader](../RE-017-local-state-restore-115/README.md) decodes its separate ABCI input first. Its result supplies the requested height at +0x28. The [selector](../RE-009-node115-restore-path-provenance/README.md) returns the matched directory in row +8/+16. On the non-sentinel arm the caller preserves this row while preparing the [live descriptor](../RE-017-node115-local-restore-live-evm-path/README.md). The descriptor starts with the live home triple and holds its typed EvmState member at +0x18. For the selected configured-root branch the home is `<base>/hyperliquid_data/evm_db_hub_slow`.

1. At `0x2cc19ea` RSI carries the historical row and RDX the live descriptor. The wrapper moves these to RDX/RCX for the [constructor](../RE-016-state-materialize-3c2e860-115/README.md); the constructor saves and restores them around its call into the [composer](../RE-016-state-compose-434b9f0-115/README.md). At `0x434bb32` the composer passes the live descriptor for preparation. On normal return the helper has copied all 48 bytes including its initial home triple. At `0x434bb4f` the same composer passes the historical row, the prepared descriptor and mode 1.
2. The [DB-home lifecycle](../RE-016-db-home-chain-115/README.md) formats the destination via callback `0x1696d50`. That callback dereferences the descriptor and emits its +8/+16 bytes. This selects the **home** as the destination operand. The caller checks this directory and requests recursive creation on the false arm.
3. For the source, `0x44682de/2e2` take the historical row's pointer/length. Formatter `0x1699c10` displays that slice. The second display argument is byte 2, and the relocated formatter takes the eight-byte `EvmState` arm. The format record spells `{}/{}`. These operands give `<selected>/EvmState`, preserving any separator already in the displayed string.
4. The first copy call at `0x4468379` passes the formatted historical source, formatted live home and flag 1 to the [adapter](../RE-009-node115-checkpoint-lifecycle/README.md). At `0x1502920` an unsuccessful source directory predicate branches out **before command assembly**. In particular a completion marker can make a height discoverable while the required source subtree is missing. On the ordinary prepared-home route the command vector contains `cp`, `-al`, source, destination, in that order.

## Reproduction

From the repository root, with the pinned artifact materialized and a Unix host whose cp supports archive and hard-link options:

```sh
python3 -B research/work-items/RE-017-first-checkpoint-copy-115/verify.py
cargo test --locked --offline --manifest-path src/node115-owned-db-open/restore-copy/Cargo.toml
```

The verifier checks the instruction bytes in [trace.tsv](trace.tsv), direct edges, ELF relocations and literal operands. The Rust fixtures use temporary trees with distinct historical and live roots, paths with spaces, a nested payload and a sibling sidecar. They check the argument vector, content and matching device/inode after invoking host cp. A missing EvmState directory, a regular file in its place, and a regular file in place of the live home all prevent command preparation. Another case checks the exact argument bytes for an already slash-terminated input path.

The source projects the first copy on ordinary stable directory inputs, after upstream selection and cleanup. Rust IO errors expose failure at the preparation boundary. Native diagnostic formatting, the adapter's alternate destination-parent branches, later checkpoint replication, the RocksDB loader and application state decoding remain outside this implementation. The inode result is an observation of the independent fixture. The first historical input here is a directory tree. Its contents alone do not identify a serialized first ABCI field.
