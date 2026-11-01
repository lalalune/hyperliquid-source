# Node94 six-word subtraction family

Independent `no_std`, safe Rust reconstruction of one coherent family:

- Saved wrapper `0x56570a0..0x56570dc`.
- Raw subtraction/correction `0x56570e0..0x5657169`.
- High-first pair wrapper `0x5657180..0x56571e3`.
- Byte-identical raw aliases `0x56580a0..0x5658129` and
  `0x565ae00..0x565ae89`, implemented by the same Raw path.
- Actual prepared-register interior entries `0x56580bb` and `0x565ae1b`,
  both inside the authenticated raw bodies.

`apply` computes `(A-B+[A<B]*M) mod 2^384` with arbitrary word values.
It returns the exact thirteen GP register observations and modifies only the
destination bytes. This is one conditional correction, not a canonical modulus
operation. Pair executes its high 48-byte block first; low A/B/M are then read
from the modified image. Arbitrary partial data aliases are supported.

Raw and Saved need 48-byte A/B/M/D spans; Pair needs 96-byte A/B/D and 48-byte M.
Prepared uses supplied R8..R13 and does not read or validate A. `saved` supplies
entry RBX/RBP/R12/R13/R14/R15 for Saved/Pair. Original stack/control storage must
be valid and disjoint from the stable, nonwrapping data image. `None` is a new
atomic bounds refusal. Flags, original ABI, fault order, stack bytes and
concurrent/MMIO observations are excluded. RDI/RCX retain D/M addresses.

The canonical closure is 296 bytes; another 274 bytes authenticate its two raw
aliases. They are not counted as separate implementations. Addition at
`0x5658000` is excluded because it exactly duplicates the separately covered
`0x5656980` addition helper. No existing addition code is reproduced here.

See the [proof](../../research/work-items/RE-004-node94-six-word-subtract-family-rust/PROOF.md)
and [evidence packet](../../research/work-items/RE-004-node94-six-word-subtract-family-rust/README.md).
The independent whole-integer/immutable-overlay oracle was frozen before Rust.
Qualification runs only new Rust through an input-only client:

```sh
python3 -O research/work-items/RE-004-node94-six-word-subtract-family-rust/validate.py --output work/node94-six-word-subtract-family/recheck
python3 -O research/work-items/RE-004-node94-six-word-subtract-family-rust/verify_recorded.py
```

The validator pins installed rustc 1.94.1 and builds directly at opt0/opt3 twice.
There are no Cargo dependencies, captured execution or whole-node build claims.
