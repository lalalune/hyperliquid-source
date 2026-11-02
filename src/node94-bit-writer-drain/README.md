# Node #94 bit-writer drain

Dependency-free `no_std`, safe Rust reconstruction of linked ELF VA
`[0x5494050,0x54940d8)` in node #94, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The descriptive name is inferred from the bytes; original source provenance
and field purposes remain unknown. This standalone crate is not a node build.

`project(State)` covers every i32 counter, u16 accumulator and u64 position.
Exactly 16 emits both accumulator bytes in little-endian order and clears the
counter/accumulator. Signed counters <=7 leave the state unchanged. All other
values emit the low byte, subtract 8 from the counter and shift the word right
8. Position increments wrap at 64 bits. The transition includes the observed
raw RAX: zero-extended counter bits on no output, old position on one byte, and
zero on two bytes. The fixed emission array zero-fills unused entries.

`drain(&mut State, &mut [u8]) -> Result<u64, OutputTooSmall>` applies the
transition and returns the observed RAX. It accepts any position on a no-output
transition. Before an emitting transition writes anything, it checks that the
position and the entire emitted interval fit the output slice. Failure leaves
both state and output unchanged. This refusal is explicit additional API
behavior; the target has no capacity check.

Correspondence assumes stable state, a mapped writable output buffer, no state /
output aliasing, and nonwrapping actual target addresses. Safe mutable borrows
provide disjoint Rust state/output. The value projection remains defined for
wrapped positions even when slice application rejects them. Original pointer
layout/ABI, faults and partial fault writes, concurrent observation/mutation,
MMIO, other registers and flags are excluded. No source-level return type is
inferred from RAX. See the [memory-order proof](../../research/work-items/RE-001-bit-writer-drain-rust-94/PROOF.md).

Build from the repository root with Rust 1.94.1:

```sh
CARGO_TARGET_DIR=work/bit-writer-cargo cargo build --offline --locked --release \
  --manifest-path src/node94-bit-writer-drain/Cargo.toml
python3 -B research/work-items/RE-001-bit-writer-drain-rust-94/verify.py \
  --out work/bit-writer-review
```

The [evidence packet](../../research/work-items/RE-001-bit-writer-drain-rust-94/README.md)
contains complete bytes/FDEs/call bindings, independently frozen expectations,
an input-only native client, repeated opt0/opt3 builds, and effective compiled
mutants. Native runs execute only this newly authored Rust. No captured target
execution, binary equivalence, whole-component completion, or recovered source
identity is claimed.
