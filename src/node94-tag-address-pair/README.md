# node94 tag-selected address pair

Independent dependency-free `no_std`, safe Rust for the numeric RAX/RDX relation
of node94 ELF VA `0x15d65b0..0x15d65f3` (67 bytes). `select(object, tag, load_bias)`
accepts a supplied qword snapshot and returns both complete register values.
It does not read memory or claim the original native pointer/return ABI.

With `H=2^63`, tags below `H` return the object and biased slot `0x5676c20`;
`H` returns object+8 and biased slot `0x5676ba8`; `H+1` returns `(0,H+1)`;
larger tags return `(0,H+2)`. Address additions wrap at 64 bits. The two slot
addresses are returned numerically; their relocated contents are not read.
The literal high-tag values are never adjusted by load bias.

Native correspondence requires a valid ordinary qword at the supplied object
with the supplied tag, valid code/control memory and the premises in the
[proof](../../research/work-items/RE-001-tag-address-pair-rust-94/PROOF.md).
No source type, runtime validity of arbitrary numeric addresses, fault/MMIO or
concurrent behavior is inferred. No captured executable or emulator is used.

From repository root:

```sh
cargo +1.94.1 check --manifest-path src/node94-tag-address-pair/Cargo.toml --locked --offline
python3 -O research/work-items/RE-001-tag-address-pair-rust-94/verify.py --out work/tag-address-pair-replay
```

The input-only client accepts tab-separated ID, object, tag and bias, with
three 16-digit hexadecimal integers, and prints ID plus `V:rax:rdx`. Exact frozen
expectations, static bindings, native results and limitations are in the
[evidence packet](../../research/work-items/RE-001-tag-address-pair-rust-94/README.md).
This standalone component does not establish a node build or completed gate.
