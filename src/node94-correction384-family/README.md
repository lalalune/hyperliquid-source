# Node94 384-bit single-correction addition family

Independent safe `no_std` Rust for complete core `[0x5656980,0x5656a13)`,
its actual interior entry `0x565699b`, single wrapper `[0x5656940,0x565697c)`
and ordered pair wrapper `[0x5656a20,0x5656a83)`. Node94 SHA-256:
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.

For arbitrary 384-bit A, B and C, compute S=A+B and return
`(S-C*[S>=C]) mod 2^384`: at most one subtraction, with no reduced-input premise.
`combine` returns six output words and all seven other written core GP values.
`apply_core` applies the stores with either a memory input or independent register
words for the actual interior entry. Incoming carry is erased by that entry's
first ADD; its incoming RSI is unused and needs no mapped input span.

`apply_single` returns nine selected wrapper observations. `apply_pair` computes
and stores high48 first, then reads low48 inputs and the correction from the
updated image. Every data alias is supported under the stated nonwrapping span
and stable-memory/control-stack-disjointness premises. Invalid ranges return None
before any store, including before the pair's high stage. Outside destination
48/96 bytes, the image is unchanged.

RDX is exactly minus the sum of the addition carry and low-sum subtraction borrow,
modulo 2^64. RAX/RSI retain original sum words 2/5, rather than corrected outputs.
Restored wrapper registers, flags, pointer ABI, fault behavior, MMIO, concurrent
changes and control state are excluded. No cryptographic or source identity is
inferred. The component has no dependencies and is not linked into a node.

```sh
cargo +1.94.1 check --locked --offline --manifest-path src/node94-correction384-family/Cargo.toml --all-targets
python3 -O research/work-items/RE-001-correction384-family-rust-94/verify.py --out work/correction384-family-replay
```

See [proof](../../research/work-items/RE-001-correction384-family-rust-94/PROOF.md)
and [evidence](../../research/work-items/RE-001-correction384-family-rust-94/README.md).
The input-only client never receives expected results. No whole-node or completion
gate claim accompanies this bounded value/image reconstruction.
