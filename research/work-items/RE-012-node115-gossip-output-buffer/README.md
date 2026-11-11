# RE-012: selected node 115 gossip output-buffer handoff

This packet follows the response-preparation call left open in [#5092](https://github.com/lalalune/hyperliquid-source/pull/5092). It targets Linux x86-64 node #115 `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. It maps selected local helper results and allocation, not a complete wire format or an actual send.

## Selected zero-marker call chain

The caller reaches `0x5a61082` with the handler-result pointer as `rsi` and a zero marker in `edx` on the selected response branches documented in #5092. `0x58616b0` saves that pointer, passes its address and the marker to `0x4e47f90`, and, on marker zero, the latter calls `0x5822f70` with the original pointer and zero in `edx`. The intervening instrumentation calls are not otherwise characterized; valid non-aliasing storage and normal ABI-preserving calls are assumptions.

`0x5822f70` initializes a local qword at stack `+0x48` to zero and calls `0x5aaac40`. If its result's low dword is not 8, the selected branch copies its 32-byte result to the output; it does not enter the selected allocation path. If the low dword is 8, let N be the qword subsequently read from local `+0x48`. The code rejects N with its high bit set; when N is zero it uses raw pointer word 1, and when N is nonzero it calls slot `0x64df480` with N. A null allocation follows a separate failure path. The internal effect and semantics of `0x5aaac40` are not inferred: N is an observed local word, not independently proven to be a serialized length.

On the nonnegative-N, normal-allocation path the function stages `(N, pointer, 0)` and calls `0x5aaa810`. If that helper returns a low dword of 8, it writes qword tag 8 followed by the three staged qwords to its output. A different tag copies a 32-byte result and conditionally calls slot `0x64df4a0` when the staged N is nonzero. The second helper's writes and complete cleanup behavior are not reconstructed here.

On the selected marker-zero continuation, `0x58616b0` tests the returned **qword** tag against 8; equality copies the following three qwords to its own output. The two inner checks use a dword; the outer check uses a qword. Different results, nonzero marker handling, helper effects, instrumentation, allocation failure and external network behavior remain open. No claim is made that the two helper calls produce equivalent byte counts or that a response was transmitted.

## Reproduce

From the repository root run `PYTHONPATH=tools python research/work-items/RE-012-node115-gossip-output-buffer/verify.py`. It authenticates the artifact, four FDE bodies, selected instructions and branches, and relocation slots. The checker reads and disassembles bytes only; it does not execute or emulate the captured target.
