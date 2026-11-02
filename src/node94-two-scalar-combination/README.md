# node94 two-scalar multiword combination

Independent safe, dependency-free `no_std` Rust for the complete node94 leaf
`0x565e7a0..0x565e956` (438 bytes). `combine` applies the ordered transformation
to one mutable memory image and returns the full numeric RAX/RDX values.

It first reads five source words, forms a scalar-dependent product with the
literal fifth-word AND correction, and stores four words. Only then does it
read eight later source words and combine the second scalar product. Arbitrary
partial and unaligned input/output aliases are supported. Signed scalar minima
and noncanonical fifth words retain their actual bit behavior.

The source interval is 104 bytes; the destination interval is 64 bytes. Both
must fit in the supplied nonwrapping image. All spans are checked before any
write; refusal leaves the image unchanged. Scalars and word values have no
additional restrictions. Native fault/MMIO/concurrent behavior, code/control
aliases, other registers and the original ABI are outside the contract.

See the [proof and domain](../../research/work-items/RE-001-two-scalar-combination-rust-94/PROOF.md)
and [evidence packet](../../research/work-items/RE-001-two-scalar-combination-rust-94/README.md).
No inferred implementation was read/copied and no captured code or emulator ran.

```sh
cargo +1.94.1 check --manifest-path src/node94-two-scalar-combination/Cargo.toml --locked --offline
python3 -O research/work-items/RE-001-two-scalar-combination-rust-94/verify.py --out work/two-scalar-combination-replay
```

The input-only client reads TSV columns: ID, image base, source address,
destination address, scalar x, scalar y, image hex (`-` for empty). Numbers are
hex u64. It reports refusal or RAX/RDX plus every changed image byte, including
any change outside the intended destination. Expected values are retained only
by the external Python comparator. This component is not a node workspace.
