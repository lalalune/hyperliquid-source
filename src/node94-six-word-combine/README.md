# node94 six-word coefficient combination

Independent `no_std`, unsafe-free Rust reconstruction of the complete 524-byte
node #94 helper `[0x565f000,0x565f20c)`, bound to SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
No field modulus, number-system purpose or caller algorithm is inferred.

`combine(image, source, destination, first_coefficient, second_coefficient)`
reads two adjacent six-word values from a 96-byte source span, mutates a
48-byte destination span, and returns the final words plus raw RAX, RDX, RBX,
R14 and R15 values. Every partial/exact overlap and both full signed 64-bit
coefficient domains are supported. Missing spans refuse before mutation;
this new API refusal does not model target faults.

The first product is stored before the second value is read. The raw arithmetic
also preserves a negative-times-zero high correction, modular 448-bit addition,
and a floor shift by 30 before sign-selective negation. Ordinary signed
multiplication or `abs(sum) >> 30` would not reproduce the full admitted domain.
Original pointer/stack ABI, flags, faults and concurrent mutation are excluded;
the [proof](../../research/work-items/RE-004-node94-six-word-combine-rust/PROOF.md)
states mapping and register premises precisely.

This standalone library has no external dependencies, Cargo workspace or build
scripts. Compile/qualify it from the repository root using installed rustc
1.94.1, commit `e408947bfd200af42db322daf0fadfe7e26d3bd1`:

```sh
python3 -O research/work-items/RE-004-node94-six-word-combine-rust/validate.py
python3 -O research/work-items/RE-004-node94-six-word-combine-rust/verify_recorded.py
```

The input-only driver receives synthetic byte images, offsets and coefficient
bits, then prints the new image and value outputs. It has no expected values.
Four opt0/opt3 native builds are compared with an independent whole-integer
oracle frozen before Rust. Only newly built Rust executes. See the
[evidence packet](../../research/work-items/RE-004-node94-six-word-combine-rust/README.md)
for controls and exact archived streams. New code/docs are MIT; imported
static artifact bytes/disassembly retain their upstream rights.
