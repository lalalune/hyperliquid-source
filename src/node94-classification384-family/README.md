# Node94 six-word classification pair

Independent safe `no_std` Rust for complete node94 bodies
`[0x56573a0,0x5657402)` and `[0x5657420,0x5657531)`, 371 bytes total.
Target SHA-256:
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.

For arbitrary unsigned 384-bit A,C, `classify` returns parity(A) plus twice
`[2A>=C]`, together with all six raw words of `(2A-C) mod 2^384` and original
parity. Full 385-bit doubling matters; no reduced-input or odd-C premise applies.
`classify_pair` selects its parity bit from low unless low is zero, and its
comparison bit from high unless high is zero. It also preserves the high tag,
low-word OR union and five final low-difference limbs in the eight selected
full GP observations. Both inputs zero and C=0 returns tag 2.

`read_single` and `read_pair` require the complete input48/input96 and correction48
spans in a stable nonwrapping image, even when a block is zero. All data aliases
and byte alignments are admitted. The image is immutable. Refusal is a new safe
API policy; original pointer ABI, faults, changing/MMIO memory and control-stack
aliases are excluded. Pair restores entry RBX/RBP; RSI and other unchanged entry
values are explicitly outside the selected output tuple. Flags and control state
are not modeled. No source, library or cryptographic identity is inferred.

The component has no dependencies or node integration. Its input-only client
never receives expected outputs.

```sh
cargo +1.94.1 check --locked --offline --manifest-path src/node94-classification384-family/Cargo.toml --all-targets
python3 -O research/work-items/RE-001-classification384-family-rust-94/verify.py --out work/classification384-family-replay
```

See [universal proof](../../research/work-items/RE-001-classification384-family-rust-94/PROOF.md)
and [evidence](../../research/work-items/RE-001-classification384-family-rust-94/README.md).
