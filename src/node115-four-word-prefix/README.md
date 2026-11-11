# Node115 private four-word prefix

Independently authored MIT `no_std` logical reconstruction of
`0x2ce1730..0x2ce198a` for node #115. See the digest-bound
[contract and evidence](../../research/work-items/RE-005-four-word-prefix-115/README.md).

`Decoder::new(input, limit, charged)` uses canonical unlimited mode for `None`,
limited mode for `Some(limit)`. `decode` performs four separately charged u64
reads, one mode-byte read, and a fifth u64 only when that byte is1. Values and
errors expose active fields only. `remaining` and `charged` retain partial
state after failure. The operation consumes a prefix, with no EOF check.

The existing MIT `node115-u64-reader-state` is the unchanged real source
dependency. Its `read_four` has different native charge ordering and is not
used. No original schema, field units, enum names or ABI are asserted.

This is a source fragment with direct `rustc` builds, not an invented Cargo
workspace or node binary. Host research builds explicitly use edition2021
and rustc1.94.1; that is not the original dependency's edition2024/rust1.95
Cargo recipe or a Linux target qualification. The packet records both
optimization profiles, frozen expectations, compiled mutants and limitations.
