# RE-012: selected node 115 request decode-error conversion and cleanup

This packet follows the helper left opaque by [PR #5069](https://github.com/lalalune/hyperliquid-source/pull/5069), on the selected request wrapper's non-`0x12` result. It is bound to Linux x86-64 node #115 `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Addresses describe selected static instructions, not a complete error API or a live execution.

At `0x5a615e1..0x5a61609`, the caller copies 32 bytes from the wrapper result to a stack temporary and passes its address to `0x5ab5b50`. That helper stages the original pointer and a formatter pointer loaded from relative-relocation slot `0x64e1940` (addend `0x1609a70`), then calls `0x5aa9050` with a format stream at `0x444d6d`. The stream starts with byte 22 followed by the exact ASCII bytes `TcpRead::bincode err: `. This identifies a formatting input, not proof that logging occurred or a complete rendering of the formatted value. The normal result in `rax` is preserved across the selected cleanup calls and returned to the caller, which places it in `r12` and sets `ebp` to 3. The meaning of the returned object is not established.

## Selected normal-return cleanup

After the formatting call returns, the helper reads the input's first byte T:

| Raw T | Selected next action |
| --- | --- |
| `< 15` or `== 16` | Return the formatting result without the two cleanup calls below. |
| `== 15` | Pass input `+0x10` to `0x5a4b8f0`; preserve and return the formatting result if that call returns normally. |
| `> 16`, qword `+8 == 0` | Return without the indirect call below. |
| `> 16`, qword `+8 != 0` | Pass qword `+0x10` as first argument, qword `+8` as second and zero as third to slot `0x64df4a0`, then return the saved formatting result. |

For T 15, `0x5a4b8f0` reads a qword W from its argument. When `W & 3` is 0, 2, or 3, its selected path returns directly. When `W & 3 == 1`, it reads two words relative to `W-1`, conditionally calls a function pointer from the second word, conditionally calls slot `0x64df4a0` for a nonzero length, then tail-calls the same slot with `W-1`, length 24, and a zero third argument. Slot `0x64df4a0` has a relative relocation addend `0x635de30`; names, dynamic binding and source-level ownership remain unproven. All observations assume valid aligned storage where required, no interfering aliases, and normal returns; unwind cleanup and malformed pointers are outside scope.

The tag rules describe local raw bytes, not a mapping to all bincode errors. No conclusion is made about diagnostic delivery, network traffic, all wrapper failures or unexamined helpers.

## Reproduce

From the repository root, run `PYTHONPATH=tools python research/work-items/RE-012-node115-gossip-decode-error/verify.py`. It checks the artifact, three FDE bodies, selected instructions, direct targets, relocation entries, the format-stream literal and static tag boundaries. It never executes or emulates the captured node.
