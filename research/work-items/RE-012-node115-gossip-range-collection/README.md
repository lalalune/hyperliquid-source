# RE-012: selected node 115 gossip range collection

This packet follows the range-view consumer left open in [#5084](https://github.com/lalalune/hyperliquid-source/pull/5084). Its target is Linux x86-64 node #115 `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The existing gossip peer snapshot and comparison packets cover different FDEs; this packet does not re-own their claims or infer the identity of this range's elements.

At `0x5a5e1ac..0x5a5e1e4`, the caller copies the range builder's 56-byte result to a temporary and passes it to `0x5acca00`. This consumer calls the iterator boundary `0x4e18c50` on that input. When the first call returns `rax == 0`, it writes output qwords `(0, 8, 0)` at offsets `0`, `+8`, and `+0x10`. This describes the local branch after the iterator returns, not all effects of the iterator itself.

## Selected nonempty ring-like view

When the first iterator call returns nonzero and the input's low dword is 1, the function computes two residual byte differences from pointer pairs at offsets `+8/+0x10` and `+0x18/+0x20`. Under the valid-view premise that each is nonnegative, is a multiple of 24, and arithmetic does not overflow, the shifts and modular multiplication by `0xaaaaaaaaaaaaaaab` produce their element counts. Let R be their sum after the first iterator call: the selected initial capacity is `max(3, R) + 1`, or equivalently `max(4, R+1)` without overflow. This does not assert how the opaque iterator advances the view or that every raw input is well formed.

The code shifts that capacity left four bits, rejects a nonzero top-four-bit overflow or a shifted byte count greater than `0x7ffffffffffffff8`, and calls allocation slot `0x64df480` only on the remaining path. Consequently the largest capacity allowed by this numerical guard is `0x07ffffffffffffff` (2^59 - 1). A null result takes a distinct failure path. These are static allocation arguments and checks, not a statement about available memory or successful allocation.

On the normal nonempty path the iterator supplies a pointer from which two qwords are read. The code performs locked increments on words addressed by those qwords, then writes the two pointers as a 16-byte pair in the allocated region. Subsequent iterator results follow the same selected two-word and increment sequence; when current length equals capacity, a separate growth helper is called. After the iterator reports zero, output qwords receive the recorded capacity, buffer pointer, and length. The precise object types, ownership rules, iterator semantics, growth behavior and full failure/unwind handling are not inferred. Claims assume valid pointers, no interfering aliases and normal calls on the selected path.

## Reproduce

From the repository root run `PYTHONPATH=tools python research/work-items/RE-012-node115-gossip-range-collection/verify.py`. It authenticates the artifact, two FDE bodies, selected instructions and branches, and static capacity boundaries. It reads and decodes bytes only; it does not execute or emulate the target.
