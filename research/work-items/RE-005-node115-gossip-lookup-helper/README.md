# RE-005: node 115 request gate's selected lookup helper

[PR #5070](https://github.com/lalalune/hyperliquid-source/pull/5070) identifies a request-result gate that calls `0x4fac7e0` and combines the returned low byte with an input dword. This packet examines that helper's conditional lookup, rather than repeating the gate. It is bound to Linux x86-64 node #115 `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

At `0x5a5dc0e`, the request handler passes the address `rsi+8` as first argument and its original `edx` value as second argument. Inside the helper, the first argument supplies an object pointer P; the second dword K is saved. The subsequent statements require valid pointers, stable non-aliasing data, and normal returns from unexamined helpers.

## Representation branch

After the selected shared-state acquisition, `0x4fac823..0x4fac829` compare zero with qword `[P+0x18]` and branch on signed overflow. The overflow branch is taken exactly when that qword is `0x8000000000000000`: this follows from the x86 flags for `0 - value`, not a comparison to a guessed source type. On every other qword, the selected code calls `0x57fafd0` with `P+0x18` and a pointer to K, then returns low byte 1 exactly when that helper returns zero. Its internal semantics are not determined here.

## Selected lookup for the sentinel representation

For the sentinel, qwords `[P+0x20]` and `[P+0x28]` supply an initial node pointer and remaining descent counter. A null initial pointer returns low byte 0. Otherwise each selected node has a 16-bit count at `+0xe6` and a sequence of dwords beginning at `+0xb8`. The loop applies `bswap` to both K and each loaded dword and compares the resulting unsigned integers. It advances while K is greater; equality returns low byte 1. At the first greater stored value it selects that position, and after exhausting the sequence it selects the count. These statements describe instruction order; they do not prove the sequence is sorted or identify the stored values as IP addresses.

For a non-match, decrementing a zero descent counter takes the no-match return (low byte 0). Otherwise the next node pointer is loaded from `node+0xe8+8*position` and processing continues. The analysis does not assert a valid acyclic structure, general termination, or runtime reachability. It does not infer the meaning of return values beyond the selected control flow.

On the shown normal return paths, the code releases the acquired state and preserves the computed low return byte even on the optional release-helper call. Contended acquisition, unwinding, helper effects, concurrent mutation, source types, and security impact remain open.

## Reproduce

From the repository root, `PYTHONPATH=tools python research/work-items/RE-005-node115-gossip-lookup-helper/verify.py` authenticates the target, both FDEs and selected instructions, control-flow targets, numeric boundary cases and byte-change controls. It parses and decodes bytes only; it never executes or emulates the captured target.
