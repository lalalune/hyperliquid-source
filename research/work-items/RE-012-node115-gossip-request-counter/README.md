# RE-012: selected node 115 request-range counter handoff

This packet follows the `B - A <= 99` branch left open in [PR #5070](https://github.com/lalalune/hyperliquid-source/pull/5070). Its target is Linux x86-64 node #115 `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. This is selected static control and data flow, not a statement about production configuration, source-level field names or a bypass.

The prior `RE-012-peer-limiter-counter-policy-115` packet studies the separate listener helper `0x595ec00`, a 20-byte key and a threshold derived from ten times a caller-supplied budget. Its saturating counter updates are related precedent; the present packet establishes the separate request handler, its `0x59db3a0` handoff, increment 1..100 and direct comparison with 10,000. It does not claim saturation as a new general algorithm.

## Range to helper input

In `0x5a5dbc0`, the selected path subtracts A from B without unsigned borrow and continues only when the difference is at most 99. After intervening calls, `0x5a5de29` increments that retained difference and `0x5a5de3c` calls `0x59db3a0` with the incremented value in `rdx` and 10,000 in `rcx`. Thus its selected increment is 1 through 100, provided ABI-preserving normal returns and no interfering state mutation. The call also receives a 17-byte stack region and an object pointer; the semantic identity of that region is not asserted.

## Selected helper update and comparison

At entry, `0x59db3a0` retains the increment and threshold in callee-saved registers. Its callback at object `+0x168` may return a nonzero low byte, immediately leading to return 0 without the update described below. On the different route that reaches `0x59db4c3`, the code adds the increment to qword `[r13-0x10]` and stores the unsigned saturating result: overflow selects `0xffffffffffffffff`. It later increments `[r13-0x8]`, also saturating at that maximum. These are two distinct qword writes; the map lookup and record identity are not reconstructed here.

At `0x59db629`, the helper compares the current qword `[r13-0x10]` with the retained threshold using an unsigned comparison. A value less than or equal to 10,000 follows the direct return-0 branch. A greater value enters additional helper-dependent paths; this packet does not claim their overall result. If intervening calls or aliases changed the qword, the comparison sees that changed value, not necessarily the earlier write. The outer caller tests the returned low byte after a lock-release sequence; no claim is made here that every request has this counter, that a zero return means admission, or that the configured threshold is global.

The call path assumes valid objects, a normal callback return, the recorded conditions, no interfering aliases where the earlier write is related to a later read, and ABI-compliant helpers. Lock contention, map insertion, callback semantics, all other counter modes and runtime behavior remain open.

## Reproduce

From the repository root, run `PYTHONPATH=tools python research/work-items/RE-012-node115-gossip-request-counter/verify.py`. It authenticates the artifact, two FDE bodies, selected instruction bytes, direct targets, and static unsigned boundary cases with mutation controls. It does not execute or emulate the target.
