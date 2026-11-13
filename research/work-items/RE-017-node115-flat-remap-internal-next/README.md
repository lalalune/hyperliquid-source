# RE-017: flat remap internal iterator descent (#115)

## Question and scope

PR #6681 establishes a zero-depth remap iterator step and leaves nonzero depth open. How is the next descriptor prepared after returning an internal entry? Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; ELF virtual addresses; main reference `a8616af9432b8d8517b2af677880e117b7c28ef3`. Iterator FDE `[0x51dfbc0,0x51dff6a)`.

## Observations

For selected descriptor tag 1, remaining count nonzero, a nonnull current node, index `i` below the node's 16-bit count and depth `d>0`, `0x51dfbce..0x51dfc19` decrements remaining count and preserves the original node, depth and index for the result. It forms the first child-pointer address `node+0x490+8*i`, corresponding structurally to child `i+1` in an array starting at `+0x488` (`0x51dfc1f..0x51dfc23`).

The remainder loop and eight-at-a-time loop follow exactly `d` child links: the first uses that selected `i+1` slot, and subsequent links use each node's `+0x488` slot (`0x51dfc2a..0x51dfc64`, `0x51dfe15..0x51dfe5f`). At `0x51dfe61..0x51dfe79`, it returns the original `(node,d,i)` and sets the input descriptor to `(last_child,0,0)`. #6680 shows the caller reads the returned original node/index to obtain its 32-byte and 72-byte fields; the new descriptor is for a subsequent call.

This is conditional on valid pointers and a depth-consistent tree; loops, allocations and helper calls have no asserted behavior outside that path. It supports an in-order descent interpretation, but does not establish global order, exhaustion, actual replay reachability, checkpoint recovery or state-root alignment. No completion gate is advanced.

## Reproduction

Run `python3 research/work-items/RE-017-node115-flat-remap-internal-next/verify.py` to authenticate the target, check four instruction anchors and one direct call, and reject four independent single-byte mutations. `windows.txt` is Apple LLVM objdump 21.0.0 `-d --x86-asm-syntax=intel` output; Python 3.11.15 was used. The target is not executed.
