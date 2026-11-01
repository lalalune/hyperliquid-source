# node94 gated block copy

Independent, dependency-free, safe `no_std` reconstruction of node #94 ELF VA
`[0x4ff8b30,0x4ff8b9c)`, target SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.

`copy_block(image, destination, source, index_source, bound, flag)` chooses a
48-byte block and copies its entry bytes into a checked destination. With a
nonzero flag it reads the little-endian i32 at index_source+20. Its wrapping
decrement must be at most the signed bound, and the byte at source+416 must be
nonzero, to select source+392. All other paths select source+344. The gate and
index are read only on the target paths that need them.

A single mutable image preserves all admitted source/destination/index/gate
aliases. Selected bytes are snapshotted before writes. The return is the
destination offset, representing the target's unchanged RAX pointer. Missing
used ranges or offset overflow return `Unavailable` without any write.
The checked refusal behavior is additional policy; native faults, concurrent or
MMIO memory, pointer wrapping, machine ABI and source-level field meanings are
outside the claim. No valid-index or Boolean-byte assumption is made.

This is a standalone component, not a full node workspace. It has no dependencies,
build script, captured code execution, unsafe code or external runtime service.
`client.rs` reads only input rows from stdin and emits status, returned offset
and lossless differences over the entire image. It never reads expectations.

From the repository root, with Rust 1.94.1 on PATH:

```sh
cargo check --offline --locked --manifest-path src/node94-gated-block-copy/Cargo.toml
python3 -O research/work-items/RE-001-gated-block-copy-rust-94/verify.py --out work/gated-copy-replay
```

The [evidence packet](../../research/work-items/RE-001-gated-block-copy-rust-94/README.md)
contains the full body/caller/FDE binding, alias proof, frozen independent oracle,
raw native streams, mutation controls and exact build commands. New code is MIT;
retained target disassembly keeps the artifact's original rights.
