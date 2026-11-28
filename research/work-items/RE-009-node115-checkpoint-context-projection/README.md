# RE-009 · Project named node #115 checkpoints into the Context root comparison

A named JSON checkpoint carries the root input fields under `exchange.locus.ctx`. This adapter checks the local checkpoint's SHA-256 and requested height, then emits all 13 normalized fields accepted by the existing [Context root comparator](https://github.com/lalalune/hyperliquid-source/pull/7352). A selected named checkpoint can now reach the Context comparison without manually assembling an intermediate JSON object.

- Both clock strings are normalized to signed Unix seconds and an exact nanosecond word. The adapter accepts the ordinary canonical formatter forms with zero, three, six or nine fractional digits. Seconds are calculated with integer calendar arithmetic, including dates before the Unix epoch.
- `consensus_round` and `round` select a single Context field, while the nested `hardfork.round` stays separate. Omitted Context round, hardfork and next TWAP identifier use the selected zero defaults.
- `tx_index` must be supplied explicitly. JSON null stays absent, and zero stays present. The remaining counters stay unsigned 64-bit values. `use_system_nonce` must be a JSON boolean.
- Duplicate relevant fields and mismatched checkpoint heights cause errors. Unrelated keys can appear outside the selected Context fields.

The [JSON clock evidence](../RE-009-node115-json-context-clocks/README.md) pins both independent clock reader calls, and [#7275](https://github.com/lalalune/hyperliquid-source/pull/7275) identifies the canonical clock spelling. The [identifier evidence](../RE-009-node115-json-context-identifier/README.md) pins the three source counters and the selected TWAP default. [#7364](https://github.com/lalalune/hyperliquid-source/pull/7364) projects the subset required for replay startup, including an independent freeze option. This adapter combines the source fields consumed by the Context subtree comparator, including the clock and counter data absent from that replay projection.

The verifier checks thirteen literal references in the native named Context writer, both clock and all three counter call sites in the JSON reader, and the transaction writer's present and absent routes. It runs the checked-in named fixture through the CLI and can submit that projected output to the existing Context comparator. The [fixture JSON](fixture.json) and [expected projection](expected.json) are synthetic, including the comparison tree created for the optional test. The adapter reads the JSON file into memory and supports the named, ordinary-clock projection. It does not extract a MessagePack checkpoint or claim full checkpoint acceptance, independent source provenance or real H/H+1 equality.

Target ELF SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Base `2da45cb0a761cff6b478e40421699857d87a94df`.

## Reproduce

From the repository root with the pinned artifact available:

```sh
packet=research/work-items/RE-009-node115-checkpoint-context-projection
python3 -B "$packet/verify.py"
python3 -B "$packet/project.py" CHECKPOINT.json --sha256 CHECKPOINT_SHA256 --height HEIGHT \
  > context.json
```

Pass the result and its own SHA-256 to the [Context comparator](https://github.com/lalalune/hyperliquid-source/pull/7352). When that packet is locally available, run the synthetic handoff check with Rust 1.95 on PATH.

```sh
python3 -B "$packet/verify.py" --comparison path/to/context-subtree-compare
```

[Measured offline output](offline-log.txt).
