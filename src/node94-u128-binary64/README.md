# Unsigned128 to binary64 returned bits

This independent, dependency-free `no_std` component exposes
`binary64_bits(u128) -> u64`. It returns the IEEE754 binary64 encoding of the
unsigned integer, rounded to nearest with ties to even. All u128 values are
admitted, including zero; the greatest result is finite `2^128`.

The source uses integer bit arithmetic. It does not call a floating conversion
or reproduce the native instruction sequence. Its numerical relation is grounded
in the complete node94 132-byte leaf at ELF VA `0x565ff80..0x5660004`, target
SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The independent native proof and frozen expectations precede this source; see
the RE-004-u128-binary64-94 evidence packet. This public scalar projection is
not a recovered original type, ABI, caller meaning or machine-code identity.

There is no Cargo dependency resolution or invented workspace. The evidence
runner invokes authenticated research rustc1.94.1 directly with edition2021,
overflow checks enabled, one codegen unit, and optimization0/3. It builds the
library, ordinary unit harness and separately linked input-only client. The
client accepts exactly one stimulus path containing `id|n32hex` rows and writes
`id|bits16hex`; expected output is compared outside the client process.

`unit-vectors.tsv` contains twenty unchanged rows selected from the independent
pre-Rust root authority. The freeze receipt records their exact bytes. There is
one ordinary Rust unit method over those twenty cases, run once per profile.
The complete production comparison uses all16,614 independent authority rows.
No captured binary or instruction evaluator is part of this build.

The library has no heap, I/O, unsafe code or floating arithmetic. New source is
MIT under the repository license; imported official-artifact bytes retain the
full upstream multi-license in the evidence packet. Research toolchain identity
does not identify the original node compiler.
