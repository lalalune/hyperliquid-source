# Node #115 implementation

These independently authored Rust components have bounded, target-specific
contracts. They are not yet one integrated node. See each README and evidence
packet for supported behavior, build commands and remaining gaps.

- `node115-latency-pair`: latency-associated numeric projections.
- `node115-nonce-ring`: conditional strict ordering of a two-span nonce ring.
- `node115-quantity-preparation`: decimal coefficient and scale preparation.
- `node115-snapshot-selectors`: selected snapshot dispatch and numeric projections.
- `node115-weighted-fastfold`: checked weight accumulation and threshold gate.
- `node115-tagged-count`: capped unsigned count over three observed tag branches.
- `node115-u128-binary64`: migrated unsigned128 to binary64 value projection.

- `node115-signed-scalar`: signed scalar values, diagnostics and retained input cursor.

The default development toolchain is Rust 1.95.0. Existing evidence runners that
explicitly pin research Rust 1.94.1 retain that compiler for reproducibility; this
does not change their node #115 target identity. Retired implementations remain
only in Git history. New code must establish its #115 contract before adoption.
