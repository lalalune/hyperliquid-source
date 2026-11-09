# RE-012: node 115 selected gossip request error display

This packet resolves the formatting target left open in [#5092](https://github.com/lalalune/hyperliquid-source/pull/5092) and relates its seven selected table entries to the raw handler codes in [#5070](https://github.com/lalalune/hyperliquid-source/pull/5070) and [#5083](https://github.com/lalalune/hyperliquid-source/pull/5083). The target is Linux x86-64 node #115 `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

The caller's selected tag-3, nonzero-marker path passes the handler output at `H+0x10` through slot `0x64ebfb8`, whose relative relocation addend is `0x5aaa0c0`. This target reads a qword tag and dispatches through seven selected signed-relative table entries based at `0x939ed4`. The first four fixed-string arms pass the literal pointer and length to a function pointer at a supplied descriptor's `+0x18`; the other three stage pointers to fields at input `+8` and `+0x10` and pass a format stream to slot `0x64df6f0`. Actual formatter behavior, runtime binding and complete rendered messages remain outside the proof.

| Raw tag | Selected display input | Previously established selected producer |
| --- | --- | --- |
| 0 | `Peer-only request` | The gated fallback in #5070 constructs code 0. |
| 1 | Format stream beginning `invalid client block range: ` | Unsigned B-A borrow constructs code 1. |
| 2 | `too many client blocks requested` | Non-borrow difference greater than 99 constructs code 2. |
| 3 | `rate limited` | The selected nonzero counter-helper return constructs code 3. |
| 4 | `no client blocks to serve` | The selected empty-cache path constructs code 4. |
| 5 | Format stream beginning `client block round too small: ` | The selected A <= first-scalar path constructs code 5. |
| 6 | Format stream beginning `client block round too large: ` | The selected A > first-scalar and B > last-key path constructs code 6. |

The strings and code-store branches are byte-backed. The associations are conditional on reaching the selected formatter with the same handler result, valid storage, normal calls and no interfering aliases. A format prefix does not establish the complete formatted output; error names do not prove units, runtime reachability, external effects or all possible enum values. The table is indexed by the raw qword and this packet does not claim safe behavior for other tags.

## Reproduce

From the repository root run `PYTHONPATH=tools python research/work-items/RE-012-node115-gossip-error-display/verify.py`. It authenticates the target, three FDE bodies, selected instruction bytes, the seven table entries, literal fragments and relocation slots. It reads and decodes bytes only and never executes or emulates the captured node.
