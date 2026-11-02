# node94 decimal-u64 parser

Independent `no_std` value projection of the complete node94 leaf
`[0x54307c0,0x5430857)`, target SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The decimal-index formatting wrapper is excluded from reconstruction.

`parse(leading_zeroes, tail, previous_output)` observes the logical byte string
`b'0'` repeated `leading_zeroes` times followed by `tail`. Ordinary strings use
a zero prefix count. The compressed prefix allows actual new Rust native runs
to test 2^31/2^32 digit-count edges without allocating or traversing gigabytes.
It is an input representation, not a claim to have executed those target reads.

The result reports raw RAX, consumed/remaining lengths, output value and whether
an output store occurred. The parser accepts the longest nonoverflowing ASCII
digit prefix. Overflow returns zero without consuming the failing digit or
writing the output. Empty input writes zero. Nondigit termination writes the
value but sets AL according to signed `(digits mod 2^32) > 0`; EOF after digits
returns RAX=1 regardless of that counter. A high-bit nondigit leaves RAX equal
to `0x00000000ffffff00` or `0x00000000ffffff01`, so raw RAX is not a Boolean.

`LengthOverflow` is a new API refusal when the logical input length exceeds
u64. Original numeric overflow remains an admitted parser outcome. The proof
assumes an immutable readable sequence and nonoverlapping state/output cells,
with valid nonwrapping native address formation. Pointer validity, faults,
state/input/output aliases and concurrent mutation are excluded. State pointer
changes are represented by consumed/remaining counts, not native pointers.

```sh
python3 -B -O research/work-items/RE-004-node94-decimal-u64-parser-rust/validate.py \
  --output work/node94-decimal-u64-parser/recheck
```

The [proof](PROOF.md) establishes the full admitted relation. The
[evidence packet](../../research/work-items/RE-004-node94-decimal-u64-parser-rust/README.md)
retains the pre-Rust lexical oracle, full static closure, native results and
raw streams. Builds use installed rustc 1.94.1 directly, without dependencies
or a root workspace.
