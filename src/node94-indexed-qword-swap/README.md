# node94 indexed qword swap

Independent, dependency-free, safe `no_std` reconstruction of node94 ELF VA
`[0x4fa90a0,0x4fa9109)`, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.

`swap_indexed(image, base, first_table, first_index, second_table, second_index)`
uses abstract u64 addresses over one mutable image. It selects each table's
pointer field at +264 for indices 0..31, or +272 for larger full u64 indices.
The selected address is the loaded base plus eight times the index (or index-32
on the high branch), modulo 2^64. This preserves high index bits in branch
selection and their truncation during scale-by-eight.

Both table fields and both eight-byte data values are read before writing the
first value to the second address and the second value to the first address.
This ordering preserves arbitrary admitted partial overlaps, including overlaps
with the pointer fields. The first selected range has final-write priority.
The return is its original computed address, corresponding to raw RAX.

The image and fixed table-field addresses must not wrap. Modular computed
addresses must each name eight available image bytes. Loaded table bases need
not themselves be mapped, and only the chosen pointer field is required.
Unavailable ranges return `Unavailable` before writes. This is a safe value/image
projection, not a native pointer ABI or a claim that every abstract address is
mappable on x86-64. Faults, MMIO, concurrency, control aliases and wrapping
memory accesses are excluded. No index bound or source-level table type is
inferred beyond the proven selection rule.

This is a standalone component, with no unsafe code, dependencies or build
scripts. Its stdin-only client emits raw RAX/status and lossless full-image
differences; it has no expected-output interface.

From the repository root:

```sh
cargo check --offline --locked --manifest-path src/node94-indexed-qword-swap/Cargo.toml
python3 -O research/work-items/RE-001-indexed-qword-swap-rust-94/verify.py --out work/indexed-swap-replay
```

The [evidence packet](../../research/work-items/RE-001-indexed-qword-swap-rust-94/README.md)
contains the complete target/caller/FDE binding, proof, frozen independent
oracle, native comparisons and limits. New code is MIT; original target
bytes/disassembly retain original artifact rights.
