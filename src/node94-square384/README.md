# Node94 scalar 384-to-768-bit square

Independent safe `no_std` Rust for the complete 528-byte / 160-instruction body
`[0x565b800,0x565ba10)`. Node94 SHA-256:
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.

`square` returns all twelve words of the exact unsigned square plus all fourteen
written GP observations, including the target's intermediate cross/diagonal
carries. Every input word has its complete u64 domain. `apply` snapshots 48 input
bytes before writing 96 output bytes, preserving arbitrary data aliases and
unaligned spans. Invalid nonwrapping image/span checks refuse without mutation.

Stable ordinary little-endian data and valid separate return/control storage
are explicit premises. Native pointer ABI, faults, MMIO, concurrency, flags and
unchanged RDI are outside this projection. A separate ADX square-shaped body at
`0x5658a00` reloads data between stores and has different alias/stack premises;
it is outside this implementation and qualification. No source, library or
cryptographic identity is inferred.

The component has no dependencies or node integration. Its input-only client
never receives expected outputs.

```sh
cargo +1.94.1 check --locked --offline --manifest-path src/node94-square384/Cargo.toml --all-targets
python3 -O research/work-items/RE-001-square384-rust-94/verify.py --out work/square384-replay
```

See [proof](../../research/work-items/RE-001-square384-rust-94/PROOF.md) and
[evidence](../../research/work-items/RE-001-square384-rust-94/README.md).
