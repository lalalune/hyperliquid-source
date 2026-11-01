# Node94 chunk-comparison family

`compare(pattern, input, object)` returns full numeric RAX, RDX and RCX
for one of twelve complete 16-byte comparison functions. Patterns follow
linked entry order `0x14b52b0 + 0x30*i`, i=0..11. The input is an exact
16-byte snapshot; the object value is only used in wrapping addition.

RDX always contains object+56 modulo 2^64. RCX contains the sixteen
byte-equality bits. RAX is RDX on a full match and zero otherwise, so a
full match may itself return zero after address wrap.

The dependency-free `no_std`, safe Rust component builds directly with
rustc. It does not recreate native pointers, ABI, SIMD state or faults.
See the [evidence packet](../../research/work-items/RE-004-chunk-equality-family-rust-94/README.md)
and [proof](../../research/work-items/RE-004-chunk-equality-family-rust-94/PROOF.md).
