# Node94 mixed-width lookup pair

A safe, dependency-free `no_std` reconstruction of the complete leaves
`[0x299e280,0x299e29e)` and `[0x29d7fc0,0x29d7fde)`. One common algorithm
uses independently bound scalar constants from their distinct `.rodata`
windows. It returns full RAX/RDX values and never dereferences returned
numeric addresses.

```rust
pub fn lookup(member: Member, index_bits: u64, load_bias: u64) -> Registers;
```

`Member::At299e280` and `Member::At29d7fc0` select the original entrypoint.
This selector is a new API argument. Only the low eight bits of `index_bits`
(original RDI) select data. RDX is the selected little-endian u64. RAX is
the member's linked signed-offset base plus load bias plus the selected
sign-extended i32, modulo 2^64. Every u64 input is accepted; all constant
array accesses are proved in bounds.

All 256 reachable u64/i32 entries per member are bound. In each physical
window the i32 entries overlap the qword bytes; there are no overlapping
relocations anywhere in those complete windows. Reachable window sizes
are not claims about source-level logical tables. See the
[proof](../../research/work-items/RE-004-mixed-lookup-pair-rust-94/PROOF.md)
and [evidence](../../research/work-items/RE-004-mixed-lookup-pair-rust-94/README.md).

Original correspondence requires unchanged runtime `.rodata` bytes,
actual module load bias and normally completing reads/return. Arbitrary
numeric biases used in tests may not represent possible machine mappings.
Runtime patches, MMIO, faults, concurrent mutation, original ABI/control,
flags, other volatile registers, pointed-object identities and compiled-byte
identity are excluded. No captured code or inferred source was copied.

From the repository root, use a fresh output directory:

```sh
python3 -O research/work-items/RE-004-mixed-lookup-pair-rust-94/verify_rust.py \
  --rustc "$HOME/.rustup/toolchains/1.94.1-aarch64-apple-darwin/bin/rustc" \
  --out work/mixed-lookup-pair-rust/replay
```

The verifier pins the actual compiler, builds this library and input-only
client at opt0/opt3, compares frozen expectations, runs compiled wrong
variants and tests, and checks repeated artifacts without normalization.
Only newly authored Rust executes. There is no Cargo dependency, root
workspace or recovered original build claim.
