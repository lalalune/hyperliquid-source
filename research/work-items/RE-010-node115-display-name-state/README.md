# Node 1.1.5 display-name state core

This is scoped partial progress for issue #3912. The earlier [#2079](https://github.com/lalalune/hyperliquid-source/pull/2079) packet mapped display-name branches and selected storage helpers; [#2846](https://github.com/lalalune/hyperliquid-source/pull/2846) implemented a decision projection with supplied duplicate and prior-rejection predicates. This contribution independently implements the selected core `0x2c76380` with a real owned 20-byte-key map, exact bytewise duplicate scan and erase/upsert mutations.

An empty name erases the caller's entry and succeeds. Otherwise byte lengths above 20 return `0xe2`, below 3 return `0xe3`, and a value matching any existing value returns `0xe4`. The scan includes the caller's own existing value and uses exact bytes, with no case folding. A unique value is inserted or replaces the caller's previous value and returns `0x1a2`. The input is a valid UTF-8 Rust string; native malformed-memory inputs are outside scope. This entry models the core, not the separate caller's prior-key gate or its 101-byte wrapper limit.

The pinned original node 1.1.5 SHA-256 is `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Six full FDEs (core, iterator, erase/upsert and their selected row helpers) and imported `bcmp` are authenticated as static evidence. `verify.py` checks 40 instruction/import facts and negative controls without executing the target. Logical `BTreeMap` ownership replaces native container ABI; allocator and unwind failures, outer authorization, rollback and runtime behavior remain unclaimed.

Three Rust tests include length and UTF-8 byte boundaries, unchanged-own-name rejection, case sensitivity, replacement and 12,000 sequential operations checked against a separate list-based Rust state model. The latter is a synthetic model comparison, not a native differential test.

```sh
cargo +1.95.0 test --offline --locked --manifest-path src/node115-display-name-state/Cargo.toml
cargo +1.95.0 test --offline --locked --release --manifest-path src/node115-display-name-state/Cargo.toml
PYTHONPATH=/private/tmp/hl35g-tooling:/private/tmp/hl-review1303-venv/lib/python3.14/site-packages python3 research/work-items/RE-010-node115-display-name-state/verify.py
```

OpenAI gpt-6.1-terra / codex-desktop authored this projection and packet; OpenAI gpt-6-astra independently reviewed selected original native evidence and source. The full unfiltered suite includes captured-instruction emulation and was not run. No target execution or emulation occurred.
