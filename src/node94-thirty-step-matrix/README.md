# node94 thirty-step matrix transform

Independent MIT, dependency-free `no_std` Rust reconstruction of complete
node #94 `[0x565f2e0,0x565f390)`, target SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.

`reduce(first: u64, second: u64, accumulator: u64) -> Registers` accepts all
entry bit patterns of R8, R9 and RBP. It preserves the thirty unsigned pair
steps, signed coefficient matrix, full wrapping accumulator, and all fourteen
explicitly written value-register results. These include the last iteration's
saved pair, packed rows and accumulator. Flags, physical ABI, unchanged RSI,
stack/return control and the preparation/caller algorithm are excluded.

The implementation tracks bounded signed matrix coefficients directly rather
than reproducing the original biased packed-row arithmetic. It still preserves
64-bit unbiasing of negative coefficients, original-first parity selection,
unsigned comparisons and the wrap in `second+2` before shifting. It does not
claim a gcd/Jacobi interpretation or exact division of a final matrix product
for arbitrary even second inputs. See the [proof](../../research/work-items/RE-004-node94-thirty-step-matrix-rust/PROOF.md).

Build and qualify the standalone library/client from the repository root:

```sh
python3 -O research/work-items/RE-004-node94-thirty-step-matrix-rust/validate.py
python3 -O research/work-items/RE-004-node94-thirty-step-matrix-rust/verify_recorded.py
```

The validator pins installed rustc 1.94.1, commit
`e408947bfd200af42db322daf0fadfe7e26d3bd1`. It runs four opt0/opt3 builds
against a 66,000-case mathematical matrix oracle frozen before Rust, then
compiles sixteen wrong variants. The input-only client has no expected values.
No captured executable, instruction emulator, unsafe code, external dependency
or fabricated Cargo/node workspace is used. Exact evidence and raw streams
are in the [packet](../../research/work-items/RE-004-node94-thirty-step-matrix-rust/README.md).
Imported static bytes/disassembly retain their upstream rights.
