# RE-012: selected node 115 request counter reset handoff

This packet connects the request-counter path of [PR #5076](https://github.com/lalalune/hyperliquid-source/pull/5076) to a conditional reset. The existing `RE-001-node115-rate-limit-coordinates` records a source Location inside `0x59db990` but does not claim its algorithm; this packet adds a caller-to-reset relation and selected writes. Target: Linux x86-64 node #115 `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

## Quotient comparison to reset

On the selected range-handler path, `0x5a5ddb7` clamps a prior signed qword to zero unless it is positive. Let the resulting unsigned value be N, divisor D be `[rbp+0x170]`, and old value O be `[rbp+0x178]`. Assuming D is nonzero and division returns normally, the code computes Q = floor(N / D), choosing a 32-bit division only when both operands fit 32 bits and otherwise a 64-bit division. It stores Q to the old-value slot only when unsigned Q > O. A second comparison sets byte `[rsp+0x48]` to exactly 1 in that case and 0 otherwise.

The descriptor passed at `0x5a5de24` begins at `rsp+0x28`, placing the selected byte at descriptor `+0x20`. The other argument is `rbp+0x18`. At `0x5617381`, helper `0x5617370` tests that byte for equality to 1; only that branch calls `0x59db990` with the same second argument. The following counter helper, separately studied in #5076, also receives this `rbp+0x18` pointer on the selected continuation. This joins reset and counter-update object arguments, conditional on normal ABI-preserving calls and no interfering aliases. The meanings and origin of N, D and O are not established; no statement is made about a clock, elapsed time or actual network reachability.

## Selected reset writes

Within `0x59db990`, after its earlier helper calls return normally, four qwords are independently tested and, when nonzero at their respective tests, explicitly written as zero at object offsets `+0x140`, `+0x188`, `+0x1e8` and `+0x1b8`, in that order. Corresponding companion qwords `+0x138`, `+0x180`, `+0x1e0`, and `+0x1b0` receive a size-derived value. These stores alone do not prove source types, object identity at runtime, or complete deletion of every record. Before these stores, two conditional traversal calls and their cleanup are present; the second traversal is additionally gated by the object's low flag bit. Their internal effects, allocation and unwind behavior are outside this packet.

All statements require the selected branches, valid non-aliasing storage, D != 0, and normal calls. No claim is made for a zero divisor or for other paths. `reset_counters` is an observed 14-byte descriptor literal, not proof that a reset occurred dynamically.

## Reproduce

From the repository root run `PYTHONPATH=tools python research/work-items/RE-012-node115-gossip-counter-reset/verify.py`. The verifier authenticates the artifact, three FDE bodies, selected instruction bytes and branches, descriptor literal, and arithmetic boundary examples. It parses and decodes bytes only; it does not execute or emulate the target.
