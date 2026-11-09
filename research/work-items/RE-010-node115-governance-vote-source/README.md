# Node 1.1.5 governance-vote state core

This is bounded partial progress for issue #3924. Prior [#2237](https://github.com/lalalune/hyperliquid-source/pull/2237) mapped the selected native vote path, and [#3379](https://github.com/lalalune/hyperliquid-source/pull/3379) addressed distinct wire-name codecs. This contribution adds an independent owned-state implementation of the selected normal-return core `0x3c33f10`, including its actual logical proposal, voter amount-row, marker and vote lookups and writes.

A missing 32-byte proposal returns `0x114`. A current tuple later than its proposal tuple returns `0x117`, then a repeated 20-byte voter returns `0x115`. A missing, zero or overflowed checked sum of that voter's amount rows returns `0x116`. On continuation each existing voter row's cursor is replaced by the later of its old cursor and the proposal cursor. The first tuple component compares signed, the other two unsigned. If a present marker has nonzero first word, a current tuple before the marker multiplies an amount below `2^62` by four; otherwise the amount is retained. A current tuple at or after that marker clears only the first marker word. The resulting amount and raw choice byte are inserted for the voter, returning `0x1a2`.

Owned maps and vectors are logical representations under valid unique keys and native row order. This is not the full action: wire decoding, signature/authorization, physical container ABI, allocation, diagnostics, unwind and rollback are excluded. Numeric roles and public types are conservative descriptions, not proven economic meanings.

The pinned Linux x86-64 node 1.1.5 image has SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Ten full FDEs retain 6,698 bytes / 1,711 instructions. The verifier binds 39 selected instruction/import/relocation facts and corruption controls, covering proposal and voter key widths, checked amount reduction, cursor writes, marker behavior and vote insertion. Static evidence is not native runtime equivalence; no target instructions were executed or emulated.

Five Rust tests cover gate precedence, overflow, cursor update, marker payload preservation, the `2^62` cutoff, all proposal/voter key-byte changes and 8,000 independent Python integer-model cases. The latter are synthetic cases, not target differential execution.

```sh
python3 src/node115-governance-vote-state/tests/reference.py
cargo +1.95.0 test --offline --locked --manifest-path src/node115-governance-vote-state/Cargo.toml
cargo +1.95.0 test --offline --locked --release --manifest-path src/node115-governance-vote-state/Cargo.toml
PYTHONPATH=/private/tmp/hl35g-tooling:/private/tmp/hl-review1303-venv/lib/python3.14/site-packages python3 research/work-items/RE-010-node115-governance-vote-source/verify.py
```

OpenAI gpt-6.1-terra / codex-desktop authored the source and packet; OpenAI gpt-6-astra independently reviewed selected native behavior and source. The unfiltered suite includes captured-instruction emulation and was not run.
