# RE-012: selected node 115 gossip range view

This packet follows the range-builder call left open by [#5083](https://github.com/lalalune/hyperliquid-source/pull/5083). It concerns the ring-like representation in `0x4dce320`, not the tree delegate or the full semantics of the bound-search helpers. The related `RE-014-gossip-cache-update-115` studies a separate cache updater and its 24-byte rows; matching layout alone does not establish runtime object identity. Target: Linux x86-64 node #115 `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

## Selected call and bounds

On the selected path at `0x5a5e18a`, the caller passes a pointer to the cache subobject and a 17-byte temporary containing qwords A and B followed by byte 0 to `0x4dce320`. The helper returns qword 0 when A > B (unsigned). Otherwise, when the cache's first qword C differs from `0x8000000000000000`, the selected ring path calls `0x57f2fb0` on A and `0x57f2c40` on B because the temporary's byte is zero. Call their raw returns I and J. These helpers' search semantics are not reconstructed here. If J < I, the selected branch returns qword 0; if J exceeds cache qword `+0x18`, another branch calls an error boundary.

## View construction

Assume C > 0, 0 <= I <= J <= the cache qword `+0x18`, valid ring storage, no arithmetic overflow, and the normal helper returns above. Let H be cache qword `+0x10`, P be cache qword `+8`, and L = J - I. For L > 0 the code sets S to I+H, subtracting C once if S >= C. Valid ring invariants must make that one subtraction sufficient. The qword-1 output contains four pointer words at offsets `+8`, `+0x10`, `+0x18`, and `+0x20`:

| Case | `+8` | `+0x10` | `+0x18` | `+0x20` |
| --- | --- | --- | --- | --- |
| L == 0 | P | P | P | P |
| L > 0 and S + L <= C | P + 24*S | P + 24*(S+L) | P | P |
| S + L > C | P + 24*S | P + 24*C | P | P + 24*(L - (C-S)) |

The zero-length case takes a separate branch and does not require the formula for S. These are raw address calculations for two selected intervals, not a claim about element type, actual contents or transport framing. The caller's subsequent consumer `0x5acca00`, the alternate representation, allocator behavior, aliasing and dynamic reachability remain open.

## Reproduce

From the repository root run `PYTHONPATH=tools python research/work-items/RE-012-node115-gossip-range-view/verify.py`. It authenticates the target, two FDE bodies and selected instructions, validates direct targets and static wrap boundary examples, and rejects selected byte mutations. It never executes or emulates the captured target.
