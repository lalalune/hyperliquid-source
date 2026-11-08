# RE-012: selected node 115 gossip response preparation

This packet continues the handler and collection paths in [#5069](https://github.com/lalalune/hyperliquid-source/pull/5069) and [#5086](https://github.com/lalalune/hyperliquid-source/pull/5086). It maps selected result branches and their common write-preparation descriptor, without claiming actual socket output or the complete serializer. Target: Linux x86-64 node #115 `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

On the selected range-collection path in `0x5a5dbc0`, the collector's three returned qwords are loaded into `r12`, `rbp`, and `r13`, and `r14d` is cleared. Following the selected normal lock-release branch, shared output stores write qword 3 at `+0`, qword 0 at `+8`, and those three collected qwords at `+0x10,+0x18,+0x20`. This is a conditional connection from the selected collection result to the handler output, assuming normal calls and no interfering aliases.

## Caller result branches

The caller stores the handler result at H = object `+0x11a8`, then tests dword `[H]`:

- If it is not 3, `0x5a61888` requests two bytes through slot `0x64df480`; on a non-null return it writes bytes `6f 6b` and stages the raw triple `(2, pointer, 2)` with marker 0. It does not prove which input variants reach this branch.
- If it is 3 and byte `[H+8]` is nonzero, the caller initializes a local triple `(0,1,0)`, stages descriptor word `0x60000020`, and calls slot `0x64ebfb8`, whose relative relocation addend is `0x5aaa0c0`. On low-byte-zero return, the resulting three local qwords are staged with marker 0; nonzero takes a separate path. The formatting target's complete behavior and runtime binding remain boundaries; [#5093](https://github.com/lalalune/hyperliquid-source/pull/5093) separately maps its selected display inputs.
- If it is 3 and byte `[H+8]` is zero, the caller stages qword `[H+0x20]` as a formatting argument to the stream at `0x44dcac`. Its prefix contains length 5 and ASCII `sent `, followed later by a length-14 ` client blocks` fragment. The formatting helper's returned three qwords are staged with marker 1. This format input does not prove any message was actually sent.

All three selected normal branches reach `0x5a61915`, which writes the staged triple to object offsets `+0xe38,+0xe40,+0xe48`, writes marker to `+0x11a1`, and builds a descriptor pointing to the 20-byte literal `send gossip rpc resp`. It then reaches the call at `0x5a61082` to `0x58616b0`. These observations stop at that call: payload encoding, write completion, external effects, error and unwind paths remain open. Claims require valid storage, selected branch conditions and normal ABI-preserving helpers.

## Reproduce

From the repository root run `PYTHONPATH=tools python research/work-items/RE-012-node115-gossip-response-preparation/verify.py`. It authenticates the target and two FDE bodies, checks selected instructions, direct and relocation targets, literals and mutation controls. It never executes or emulates the target.
