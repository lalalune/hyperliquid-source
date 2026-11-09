# RE-012: selected node 115 gossip cache range checks

This packet follows the request-handler continuation left open by [#5070](https://github.com/lalalune/hyperliquid-source/pull/5070) and [#5076](https://github.com/lalalune/hyperliquid-source/pull/5076). Existing `RE-014-gossip-cache-update-115` describes a separately measured cache updater, its dual representation and last-row selection. This packet adds selected request-side first/last reads and range outcomes; equal offsets alone do not prove both calls operate on the same runtime object. Target: Linux x86-64 node #115 `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

## Preconditions and ring-like branch

Let A and B be the qwords loaded from the selected request. Consider only the zero-tag route where B - A has no unsigned borrow and is at most 99, the counter helper returns low byte 0, both selected lock operations take their uncontended normal paths, and all pointers and helper returns are valid. At `0x5a5df0e` the code loads a shared pointer S from the retained input object and acquires a byte lock at S+0x10. The qword S+0x48 selects the ring-like branch when it differs from `0x8000000000000000`.

On that branch a zero qword at S+0x60 takes the raw result-code 4 path. Otherwise define C = S+0x48, P = S+0x50, H = S+0x58, and N = S+0x60, where each denotes the qword loaded at the stated offset. Under valid ring invariants and no arithmetic overflow, the code applies at most one subtraction of C to H and to H+N-1. The resulting first and last indices select 24-byte rows in P. It loads a pointer X from first-row `+8`, and qword L from last-row `+0`. The instructions themselves do not establish ring invariants, allocation size, ordering or source types.

Let M = `0x8000000000000001`. The front scalar F is selected from X as follows: if `[X+0x28] == M`, read `[X+0x60]`; otherwise if `[X+0xb8] == M`, read `[X+0x58]`; otherwise read `[X+0xe8]`. These are the exact selected loads, not a claim about the semantic names of the words.

## Range-dependent continuation

At `0x5a5e159`, unsigned A <= F takes the raw result-code 5 path. Otherwise B > L takes raw result-code 6. With A > F and B <= L, the code passes the two qwords A and B and a zero byte to `0x4dce320`, then passes its returned 56-byte area to `0x5acca00`. Their behavior and returned payload are not reconstructed. The code-4, code-5 and code-6 paths construct a result through the shared output stores after the selected lock release. Equality therefore takes code 5 at the first comparison and reaches the later helper path at the second comparison. These are local branches, not claims about what a remote peer sees or whether the request is accepted.

The tree representation, contended lock paths, possible intervening alias writes, complete helper results, and dynamic reachability remain open. The arithmetic examples in the verifier are checks of these decoded predicates, not target execution.

## Reproduce

From the repository root run `PYTHONPATH=tools python research/work-items/RE-012-node115-gossip-cache-range/verify.py`. The checker authenticates the target and FDE, selected instruction bytes and direct branches, and exercises raw comparison boundaries and mutation controls. It does not execute or emulate the target.
