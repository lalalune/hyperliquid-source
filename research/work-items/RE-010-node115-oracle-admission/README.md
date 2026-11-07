# RE-010 · Node #115 validator reference-oracle payload admission

Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

The selected decoder for `validatorL1UpdateReferenceOracle` supplies `oraclePxs`, `externalPerpPxs` and `scalarUpdates` to `0x56b4a70`. Its successful path selects internal tag `0x9e`. The selected execute copy dispatches this tag to `0x552f980`, which calls `0x54cd990` at `0x552ff61` after its preceding checks succeed. This packet documents admission and collection bounds for that core call, separate from the existing oracle persistence evidence.

The core preserves the payload pointer from the fourth argument. A null lookup pointer at state `+0x1928`, or exhaustion of the selected key search, produces result word `0x2c` before the payload limits. After the lookup and the call through `0x64e79b0`, result word `0x1a2` allows the first collection path. Other words are copied to the core's output.

| Payload path | Count offset and unsigned bound | Result when over bound |
| --- | --- | --- |
| The word at `+0x40` differs from signed minimum | `+0x50`, at most 100 | `0x158` |
| The word at `+0x58` differs from signed minimum after the first optional collection path | `+0x68`, at most 100 | `0x158` |
| After the optional collection paths, including when both are absent | `+0x18`, at most 10,000 | `0x158` |
| After the preceding collection path joins at `0x54cdbb3` | `+0x38`, at most 10,000 | `0x158` |

The two paths capped at 100 read their pointer at `+0x48` or `+0x60` respectively, use the same relocated callee `0x43099f0`, and check its result before continuing. The table uses memory offsets because it does not trace the decoder's per-field dataflow far enough to assign the four count lanes to named wire fields. The packet does not establish committed oracle writes or replay success.

Run `python3 research/work-items/RE-010-node115-oracle-admission/verify.py` from the repository root. The verifier authenticates the ELF and checks the selected dispatch cells, field relocations, lookup and limit instructions. It rejects changed branch and limit bytes in memory.
