# Node94 384-bit parity-add/halve family

Safe dependency-free `no_std` Rust reconstruction of three complete bodies:
core `0x5656b20..0x5656bb9`, single wrapper `0x5656bc0..0x5656c2a`, and repeated
wrapper `0x5656aa0..0x5656b0b`. Target SHA-256:
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.

For every 384-bit A and C, one step is `floor((A+(A mod2)*C)/2)`, retaining
the 385th addition bit. `step` returns the six result words and six auxiliary
register values. `apply` writes the single or repeated result to a safe byte
image and reports nine wrapper register values. In repeated mode a zero low32
count means 2^32 iterations; high count bits are ignored. All counts are computed
with at most 384 direct steps plus bounded modular exponentiation, including
even/zero corrections and unreduced operands.

The image API validates all three 48-byte spans before mutation. Arbitrary data
aliases are supported by snapshots before stores. Native correspondence requires
stable ordinary memory, valid nonwrapping addresses and control-stack disjointness.
Invalid safe-image ranges return None unchanged; this is not native fault behavior.
Registers restored from entry, flags, stack/control state, MMIO, concurrency and
timing are excluded. `step` is a numeric snapshot API, not the core's pointer ABI.
No source/library/cryptographic identity is inferred.

```sh
cargo +1.94.1 check --locked --offline --manifest-path src/node94-halving384-family/Cargo.toml --all-targets
python3 -O research/work-items/RE-001-halving384-family-rust-94/verify.py --out work/halving384-family-replay
```

The input-only client consumes synthetic TSV and has no expected results.
[Proof](../../research/work-items/RE-001-halving384-family-rust-94/PROOF.md) and
[evidence](../../research/work-items/RE-001-halving384-family-rust-94/README.md)
state the exact output tuples and all-input/count argument. This component is
standalone, not linked into a node; no project completion gate changes.
