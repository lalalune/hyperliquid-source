# RE-017: replay internal-node merge child transfer (#115)

## Question and scope

PR #6668 describes the low-count leaf merge and explicitly excludes the deeper child transfer. What happens when the merged nodes are internal? Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; addresses are ELF virtual addresses. Reference main revision: `a8616af9432b8d8517b2af677880e117b7c28ef3`. Helper FDE: `[0x4c9fa80,0x4c9fe85)`.

## Selected observations

Let the pre-merge left and right counts be `L` and `R`. Under the helper's existing guard `L+R+1<12`, valid nonoverlapping nodes and child arrays, valid child pointers, correctly resolved `memcpy` and normal return, the field and parent updates in #6668 precede this branch. When the descriptor parent depth is at least two, `0x4c9fd11..0x4c9fd49` copies the `R+1` qword child pointers from the right node's child array at `+0xe8` into the left node's array beginning at child index `L+1`.

The remainder and unrolled loops at `0x4c9fd4f..0x4c9fdf9` update each copied child's first qword to the left node and its 16-bit `+0xe4` field to the new child index. The subsequent indirect call uses the right node with a size argument `0x148`, whereas the shallow branch described in #6668 uses `0xe8` (`0x4c9fcea..0x4c9fe02`). The callee's semantics are outside this packet. Inference: the selected internal merge moves ownership of the right node's children to the surviving left node.

Static evidence does not show that these states occur in real replay, prove allocator behavior, child ordering or full balancing, or establish checkpoint or state-root correctness. Error and exceptional branches remain out of scope. No completion gate is advanced.

## Reproduction

Run `python3 research/work-items/RE-017-node115-replay-internal-merge/verify.py` to authenticate the target and check seven anchors and seven independent one-byte mutations. `windows.txt` is Apple LLVM objdump 21.0.0 `-d --x86-asm-syntax=intel` output; `relocations.txt` has the relevant `readelf -rW` entries. Python 3.11.15 was used. This process does not execute target code.
