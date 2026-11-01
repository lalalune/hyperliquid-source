# Node94 u256 bound checks

Independent safe `no_std` Rust value reconstruction of the complete 69-byte
helper `[0x565dd80,0x565ddc5)` and its 104-byte fixed-bound wrapper
`[0x5651e50,0x5651eb8)`. Target node94 SHA-256:
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.

`compare_nonzero(left,right)` accepts all four-word little-endian snapshots.
RAX is one exactly for `0 < left < right`. `compare_bound(left)` closes the
actual wrapper and its exact 32-byte bound; RAX is one exactly for `left < BOUND`,
including zero. The returned `Registers` also preserve all bits of RDX, RSI and
the four difference words in R8..R11. The wrapper's RDX is `left == 0`; the
helper's RDX is always one. RSI is the all-ones/zero unsigned-borrow mask.

The API is a numeric snapshot projection, not the original pointer ABI.
Correspondence requires valid stable readable 32-byte spans, little-endian
values matching snapshots, exact read-only constant mapping for the wrapper,
and control-stack/data disjointness. Overlapping operands are admitted when
their snapshots agree with the same memory. There are no data writes. SIMD,
flags, control state, MMIO, faults, concurrent modification and arbitrary invalid
pointers are excluded. No cryptographic or source-library identity is inferred.

Build independently with no third-party dependencies:

```sh
cargo +1.94.1 check --locked --offline --manifest-path src/node94-u256-bound-check/Cargo.toml --all-targets
python3 -O research/work-items/RE-001-u256-bound-check-rust-94/verify.py --out work/u256-bound-check-replay
```

The input-only client consumes ID/mode/left/right TSV and prints seven full-width
observations. It never receives expected results. See the [proof and domain](../../research/work-items/RE-001-u256-bound-check-rust-94/PROOF.md)
and [evidence packet](../../research/work-items/RE-001-u256-bound-check-rust-94/README.md).
This component is not linked into a node and advances no project completion gate.
