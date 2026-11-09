# Node 1.1.5 claim-rewards row writer

This is scoped partial progress for issue #3912. It implements the selected normal-return row writer at `0x3c17fc0` in independent Rust. The earlier [#2157](https://github.com/lalalune/hyperliquid-source/pull/2157) packet traced the action dispatcher, writer and later balance/event boundaries, but explicitly left an independent Rust implementation unmeasured. The earlier node #94 work #403 concerns a different release.

The owned entry looks up a 20-byte user key and walks that user's rows in supplied native iterator order. Missing user and no nonzero rows return `0xaa`; nonzero rows whose conversion does not fit or whose pending word is below the floor produce `0xab`, unless at least one qualifying row makes the final result `0x1a2`. A qualifying row clears its pending word, saturating-adds the original amount to its claimed word and appends the key and amount. The floor uses actual metadata: `floor(100000000 * 10^(selected.width-selected.decimals) / 10^(first.width-selected.decimals))`, with a wide numerator and a u64 quotient fit check. Valid metadata indices and exponent differences are required. Local `Fault` values represent excluded native panic paths; earlier writes remain visible if a later row faults.

The map and vector are logical owned representations. This projection assumes valid unique users and unique row keys in native iterator order, normal returns from lookup and diagnostics, and successful allocation. It does not model physical map ABI, allocator failure, panic unwinding, rollback, subsequent balance or event processing, or end-to-end action dispatch.

The static packet authenticates the original node 1.1.5 image SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` and retains six complete FDEs covering the writer, lookup, iterator and arithmetic helpers. Its instruction and relocation checks and negative controls are selected evidence, not runtime equivalence. The independent Python integer generator creates 10,000 synthetic cases consumed by the Rust tests; it does not execute the target.

```sh
python3 src/node115-claim-rewards/tests/reference.py
cargo +1.95.0 test --offline --locked --manifest-path src/node115-claim-rewards/Cargo.toml
cargo +1.95.0 test --offline --locked --release --manifest-path src/node115-claim-rewards/Cargo.toml
PYTHONPATH=/private/tmp/hl35g-tooling:/private/tmp/hl-review1303-venv/lib/python3.14/site-packages python3 research/work-items/RE-010-node115-claim-rewards-source/verify.py
```

OpenAI gpt-6.1-terra / codex-desktop authored the source and evidence; OpenAI gpt-6-astra independently reviewed the selected native contract. No target execution or emulation was performed. The unfiltered test suite includes captured-instruction emulation and was not run.
