# node94 unsigned clamp

Independent dependency-free safe `no_std` Rust for the complete
`[0x15e4f70,0x15e4fb5)` node94 function. It returns the full original RAX
and RCX values from copied qword fields:

- Full tag zero: RAX is `min(second, cap)`.
- Low32 tag one: RAX is `min(first.saturating_sub(second), cap)`.
- Other tags: RAX is zero.
- RCX is always the full cap value.

`tag` represents the original little-endian qword at object+0. The optional
`first`, `second` and `cap` values represent fields at +16, +24 and +40.
The API checks only the selected path's required values, in original load
order. Cap is mandatory even for other-tag zero results. An unavailable
required value returns `Err(Unavailable)`; no data is mutated.

This is a supplied-value projection, not the original pointer ABI. It
requires supplied values corresponding to stable ordinary original reads
and valid code/return control. It does not model native faults, MMIO,
concurrency, access traces, flags or RET/RSP effects. `None` means a value
was not supplied; it does not describe a process mapping. No valid tag enum,
source-level type or field meaning is inferred.

Build with Rust 1.94.1:

```sh
cargo +1.94.1 check --offline --locked --manifest-path src/node94-unsigned-clamp/Cargo.toml
```

The stdin-only standard-library client is separate from the `no_std`
library. Full target/caller evidence, proof, original pre-Rust oracle,
explicit post-Rust coverage supplement and preserved initial control
failure are in [the evidence packet](../../research/work-items/RE-001-unsigned-clamp-rust-94/README.md).
