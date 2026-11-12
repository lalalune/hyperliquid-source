# RE-017: remap iterator selected exhaustion (#115)

## Question and scope

PR #6681 follows a successful leaf iterator step and excludes exhaustion. What does `0x51dfbc0` return to its remap caller when the stored remaining qword reaches zero? Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; ELF virtual addresses; main reference `a8616af9432b8d8517b2af677880e117b7c28ef3`. Iterator FDE `[0x51dfbc0,0x51dff6a)`.

## Selected behavior

When descriptor `+0x40` is zero, `0x51dfc69` saves its tag, node and depth, then writes zero to the descriptor's first qword. For tag 1 and a nonnull node, it follows successive node pointers at `+0x160`. For each visited node it calls the function through slot `0x64df4a0` with the node, a size argument of `0x488` when the current depth is zero and `0x4e8` otherwise, and zero as the third argument. It increments the depth between successive nodes and writes zero to the first output qword once the chain ends (`0x51dfc85..0x51dfcf2`). The relocation is `R_X86_64_RELATIVE` with addend `0x635de30`; the callee's semantics are not reconstructed here.

The remap caller checks the iterator output's first qword at `0x5b7a92b..0x5b7a936`. Zero selects `0x5b7af77`, which constructs the empty three-qword output `(0,8,0)` before further descriptor cleanup. This is separate from the successful leaf and internal steps in #6681 and #6682. Assuming a valid finite chain, no arithmetic wrap or alias interference, a correctly resolved relocation and normal calls, it explains the selected exhaustion return. Null-node, other tags, failures and full cleanup are not established. Static analysis does not demonstrate actual replay reachability, allocator correctness, checkpoint recovery or state-root alignment. No completion gate is advanced.

## Reproduction

Run `python3 research/work-items/RE-017-node115-remap-iterator-exhaustion/verify.py` to authenticate the target, check four anchors and one direct call, and reject four independent single-byte mutations. `windows.txt` uses Apple LLVM objdump 21.0.0 `-d --x86-asm-syntax=intel`; `relocation.txt` uses `readelf -rW`. Python 3.11.15 was used. Captured code is not executed.
