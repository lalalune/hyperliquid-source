# RE-017 · Read retained replay predecessor bytes from the decoded quorum

The [retained batch trace](https://github.com/lalalune/hyperliquid-source/pull/7306) identifies the expected identity and 32-byte predecessor comparison in `0x4fadcc0`. The incoming field can now be read directly from a decoded replay fixture. The normal result of the quorum decoder places the raw 32-byte wire hash at output `+0x48`. Through the header and Block owner copies, the selected quorum contributes the validator's identity and predecessor together.

| Incoming parent | Predecessor in decoded Header | Predecessor in retained Block owner |
| --- | --- | --- |
| Direct quorum | `+0x68..+0x87` | `+0x78..+0x97` |
| Timeout with embedded quorum and absent optional quorum | `+0x60..+0x7f` | `+0x70..+0x8f` |
| Timeout with present optional quorum | `+0xf0..+0x10f` | `+0x100..+0x11f` |

The validator's chosen owner views are `+0x30`, `+0x28` and `+0xb8` respectively. From the chosen view, it compares the identity at `+0x30` and both 16-byte halves at `+0x48` and `+0x58`. The verifier follows all 32 source bytes through each copy, including the split copies on the embedded timeout route. The existing [parent selector](../RE-017-node115-replay-parent-projection/README.md) supplies the shared quorum selection and separate timeout successor source.

`replay_retained_parent_link` returns the selected quorum's identity scalar and raw predecessor bytes. The three offline wire fixtures use distinct hash values for the Block's attachment-digest vector, the embedded quorum and the optional quorum. Both timeout fixtures check that the timeout value remains the separate successor basis. A caller can compare these observations with expected values supplied from the preceding retained Block. The projection covers the incoming operand. Source bytes for the preceding Block's expected value and both state-root comparisons remain outside this fixture.

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Source base `2da45cb0a761cff6b478e40421699857d87a94df`.

## Reproduce

```sh
python3 -B research/work-items/RE-017-node115-replay-decoded-parent-link/verify.py
cargo test --locked --offline --manifest-path src/node115-client-block-success/Cargo.toml
```

The [raw offline log](offline-log.txt) records selected ELF checks, all three byte joins and the Rust fixture results.
