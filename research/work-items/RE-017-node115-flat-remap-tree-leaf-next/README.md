# RE-017: flat remap tree leaf iterator (#115)

## Question and scope

PR #6680 maps the non-tag-2 remap path's returned node and index, but leaves iterator `0x51dfbc0` opaque. This packet follows one leaf-level successful next step. Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; ELF virtual addresses; main reference `a8616af9432b8d8517b2af677880e117b7c28ef3`. FDE `[0x51dfbc0,0x51dff6a)`.

## Observations

`0x5b7a926` calls the iterator with the remap descriptor. The selected iterator path requires descriptor `+0x40` nonzero, tag 1, node pointer `+8` nonnull, depth `+0x10` zero and index `i=+0x18` below the node's 16-bit count at `+0x482` (`0x51dfbce..0x51dfc19`). It first decrements descriptor `+0x40`. On this leaf path, it writes `(node, 0, i)` to the caller's result and updates the descriptor's node to the same pointer, depth to zero and index to `i+1` (`0x51dfe0c`, `0x51dfe61..0x51dfe79`).

On the caller's nonnull result, #6680's code uses the returned `node` and original `i` to read 32 bytes from `node+32*i` and 72 bytes from `node+0x168+72*i`. Therefore, under valid descriptor/node layout and absent alias interference, consecutive successful leaf steps consume successive entries and reduce the stored remaining qword by one each time. This does not prove the initial count, valid global tree order, exhaustion cleanup, other tags or depths, actual call reachability, checkpoint recovery or state-root equivalence. No completion gate is advanced.

## Reproduction

Run `python3 research/work-items/RE-017-node115-flat-remap-tree-leaf-next/verify.py` to authenticate the target, check four instruction anchors and one direct call, and reject four independent one-byte mutations. `windows.txt` uses Apple LLVM objdump 21.0.0 `-d --x86-asm-syntax=intel`; Python 3.11.15 was used. The target is not executed.
