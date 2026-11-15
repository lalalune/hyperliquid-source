# RE-017: remap iterator selected parent ascent (#115)

## Question and scope

PRs #6681 and #6682 cover iterator steps when the current index is below the node count. What happens when that index is exhausted but the iterator still has remaining entries? Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; ELF virtual addresses; main reference `a8616af9432b8d8517b2af677880e117b7c28ef3`. Iterator FDE `[0x51dfbc0,0x51dff6a)`.

## Observations

For tag 1, nonzero descriptor `+0x40` and a nonnull current node, the iterator decrements the remaining qword and compares descriptor index with the node's 16-bit count at `+0x482`. If index is greater than or equal to that count, it enters `0x51dfda4`. Each selected ascent reads a pointer at current node `+0x160`, reads a 16-bit index from current node `+0x480`, calls through slot `0x64df4a0` on the current node with size `0x488` for depth zero or `0x4e8` otherwise, advances depth and compares the saved index with the next node's `+0x482` count (`0x51dfdc0..0x51dfdfa`). A null next pointer takes a separate branch not analyzed here.

If the saved index is below the next node's count, the helper resumes the nonzero-depth selected-entry path at `0x51dfc1f`; #6682 records its resulting descriptor and child descent. If not, it continues upward. Under valid finite parent links, nonwrapping depth, correct relocation and normal indirect-call returns, this supports an inference that exhausted nodes are discarded while searching for the next ancestor entry. The callee's exact semantics, terminal error branch, ownership safety and full iteration order remain unproven. No real execution, checkpoint recovery, state-root alignment or completion gate is claimed.

## Reproduction

Run `python3 research/work-items/RE-017-node115-remap-iterator-ascend/verify.py` to authenticate the target and check three anchors and three independent single-byte mutations. `windows.txt` is Apple LLVM objdump 21.0.0 `-d --x86-asm-syntax=intel` output; `relocation.txt` uses `readelf -rW`. Python 3.11.15 was used; no target code is executed.
