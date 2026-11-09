# Node 1.1.5 TWAP action wire composition

Issue #3912 remains open. This packet binds the selected `twapOrder` and `twapCancel` dispatcher arms to their MessagePack writers and supplies an owned, offline encoding of their successful paths. It credits prior quantity preparation (#1323) and cancel decoding (#2202); neither provides this complete paired encoding.

The dispatcher selects raw tags `0xa9` and `0xaa`, supplying the `type` key and respective action names. The cancel writer emits `a` and `t`. The order writer emits a six-field nested record and optional details, including trigger and string option branches. Array and map modes are represented by an enum; malformed native mode values are outside the contract. The `s` quantity uses the existing quantity preparation source, followed by the selected positive decimal formatting path. The dependency source and helper are pinned in MANIFEST.sha256.

This is an encoding-only projection for valid booleans, quantity below 2^63, strings no longer than u32::MAX, and successful allocation/writes. Owned errors do not model native failure tags, partially written buffers or unwind behavior. It does not claim signing, transport, or a complete action protocol.

The pinned node 1.1.5 image SHA-256 is `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. `records.json` retains selected dispatcher, writer, formatter and primitive instruction evidence; `verify.py` checks the image, relocations, bytes and negative controls without executing the target. `reference.py` independently generates 6,000 synthetic object-packer cases consumed by the Rust tests.

```sh
PYTHONPATH=/private/tmp/hl35g-tooling:/private/tmp/hl-review1303-venv/lib/python3.14/site-packages python3 research/work-items/RE-010-node115-twap-action-wire/verify.py
cargo +1.95.0 test --offline --locked --manifest-path src/node115-twap-action-wire/Cargo.toml
cargo +1.95.0 test --offline --locked --release --manifest-path src/node115-twap-action-wire/Cargo.toml
```

OpenAI gpt-6.1-terra / codex-desktop authored this projection; OpenAI gpt-6-astra independently reviewed selected native evidence and source. The full unfiltered suite was not run because it includes captured-instruction emulation. No target execution or emulation was performed.
