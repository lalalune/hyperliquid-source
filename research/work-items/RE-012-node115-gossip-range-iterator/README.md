# RE-012: selected node 115 two-interval range iterator

This packet resolves the ring-like iterator boundary left open in [#5086](https://github.com/lalalune/hyperliquid-source/pull/5086), using the two-interval view construction recorded in [#5084](https://github.com/lalalune/hyperliquid-source/pull/5084). Target: Linux x86-64 node #115 `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Findings are static and limited to the selected representation.

## One iterator step

The constructor's selected ring result has qword tag 1 followed by interval pointers `(b1,e1,b2,e2)` at offsets `+8,+0x10,+0x18,+0x20`. `0x5acca00` passes the view to `0x4e18c50`. The iterator tests the complete first qword for zero, then tests its low dword for equality to 1; the selected view satisfies the latter. Other representations are outside this packet.

If `b1 != e1`, the selected step stores `b1+24` as the next first begin, returns the old `b1` in `rax` and `b1+8` in `rdx`. If `b1 == e1`, it moves `(b2,e2)` into the first pair and places the old empty first pair in the second. If the new first pair is also empty, it returns `rax=0` and `rdx=8`; otherwise it performs the same 24-byte step on the new first pair. `0x5acca00` checks `rax` before dereferencing `rdx`, and on a nonzero result loads qwords at `rdx` and `rdx+8`. Thus, for a valid nonzero row pointer, the collected pair consists of the row's qwords at offsets `+8` and `+16`; the row's first qword is not one of those two loads.

## Consequence for the selected collector

Assume both intervals are valid, non-overlapping, nonzero-address row ranges whose lengths are multiples of 24; pointer additions and total lengths do not overflow; the view and row memory are not altered by intervening calls; and all calls return normally. If the two initial intervals contain N rows, the selected iterator yields exactly N nonzero row pointers and then returns zero. When N > 0, after the first yield the residual two-interval count used by #5086 is N-1. Its recorded initial-capacity expression therefore reduces to `max(4,N)` for this selected valid ring view. N = 0 follows the collector's separate empty-output path.

This does not identify the qword payloads, prove row order or shared-object identity, characterize the tree representation, or establish dynamic behavior. In particular no claim is made for malformed intervals or zero-address nonempty rows.

## Reproduce

From the repository root, run `PYTHONPATH=tools python research/work-items/RE-012-node115-gossip-range-iterator/verify.py`. It authenticates the artifact and three FDE bodies, checks selected byte spans and direct targets, and checks static interval-count examples. It never executes or emulates the captured target.
