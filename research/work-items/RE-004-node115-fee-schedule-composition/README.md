# RE-004: node #115 fee schedule gate composition

This packet accompanies the independent Rust library
`src/node115-fee-schedule-compose` and advances issue #3913. It composes
previously documented normal-path relations; it does not reconstruct fee
selection, calculate a charge, or reach a ledger. No component gate is changed.
The pinned Linux x86-64 node #115 is 105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

## Evidence and contribution

The implementation joins the target-derived record sources and gates described
in existing packets: #2153 (`RE-001-node115-fee-schedule-gate`), #2162
(`RE-001-node115-fee-schedule-sources`), #2169
(`RE-001-node115-fee-schedule-finite`) and #2176
(`RE-001-node115-fee-schedule-post`). The caller owner is
`0x36a1c20..0x36a31ff`; its ordered-window helper is
`0x36e1b10..0x36e1b81`, the finite scanner is
`0x3d3b6c0..0x3d3bb55`, and the floor helper is `0x36a58d0..0x36a5d40`.
Those earlier packets retain source bindings, disassembly, FDEs, constants and
negative controls; they are credited, not duplicated as new native discoveries.
This work adds a source-owned composition with explicit supplied floor results.

The API distinguishes input tiers, secondary records, stake pairs, scalar
fields and the record +24 values produced in native iterator visitation order.
It checks finite values, ordering, stake and scalar ranges, the ordered sum,
the two floor results and the later cross/add bounds. It short-circuits the
floor callback in observed order. Outcome aggregates all rejections; no
particular diagnostic or first-failure effect is claimed. The user-supplied
floor result is an interface boundary, not an implementation of the helper.

The required conditions are valid stable inputs, normal ABI-preserving helper
returns, an accurate visitation sequence, and binary64 round-to-nearest ties
to even with masked exceptions and DAZ/FTZ disabled. The caller's floor
callback must not mutate inputs, FP controls or other relevant state. Native
allocation, iterator ownership, diagnostics, unwind, full floor arithmetic,
financial units, selected fee, ledger effects and native code identity remain
unproved. No captured code, target emulation, network or chain activity occurs.

## Reproduction and limits

`verify.py` reuses the four earlier authenticated target-certificate producers;
it checks nine source-slice bindings, the finite coverage and two floor call
records, and exercises three semantic counterfactuals (sum branch, positive
minimum, and floor argument). Those controls check the selected certificate
facts, not full binary equivalence or all implementation behavior.

```sh
python3 research/work-items/RE-004-node115-fee-schedule-composition/verify.py
cargo test --offline --manifest-path src/node115-fee-schedule-compose/Cargo.toml
cargo test --offline --release --manifest-path src/node115-fee-schedule-compose/Cargo.toml
cargo clippy --offline --manifest-path src/node115-fee-schedule-compose/Cargo.toml --all-targets -- -D warnings
```

Nine Rust integration tests cover empty and prior published schedules, gate and
floor ordering, finite values, signed zero, strict and non-strict equality,
stake caps, post-floor boundaries, negative values and sum overflow. The prior
Python target-backed model's three selected tests also pass. These are bounded
fixtures and conditional models, not a native differential run. Full `make
test` remains unrun because the unfiltered suite includes captured-instruction
emulation, which is not authorized for this work.
