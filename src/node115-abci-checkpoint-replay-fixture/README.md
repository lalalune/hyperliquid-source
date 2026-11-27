# `node115-abci-checkpoint-replay-fixture`

Bounded, offline, synthetic Rust integration crate connecting the four reviewed node #115 checkpoint/replay pilot contracts (`qcp-first-replay-key`, `qcp-expected-root-provenance`, `qcp-root-selector`, `qcp-root-cell-writer`) for `qcp-checkpoint-replay-root-fixture`.

- Target: Linux x86-64 node #115 (`artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).
- Links owned node #115 crates: `node115-checkpoint-discovery`, `node115-digest-vote-admission`, `node115-digest-support-gate`, and `node115-digest-reference-handoff`.
- Strictly separates locally produced state roots (`ctx + 0x400`, populated AFTER comparison by `0x5a07ec0 -> 0x5a03fa0`) from externally expected roots (`S + 0x3e50`, populated by action `0xdd` votes through `0x5869400 -> 0x5afadd0 -> 0x537aa60` and drained by `0x54897e0 -> 0x5afa030`).
- Offline synthetic data only; does not execute captured binaries, verify live signatures, or claim full `storage`/`abci` component completion.
