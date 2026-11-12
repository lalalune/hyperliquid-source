# RE-017: post-traversal small-map transition (#115)

## Question and scope

PR #6676 identifies the tracker qword decremented in selected tree traversal. What happens to the pending-map descriptor after that traversal when the resulting qword is small? Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; ELF virtual addresses; main reference `a8616af9432b8d8517b2af677880e117b7c28ef3`. Processing FDE `[0x4de0540,0x4de0907)`.

## Selected observations

After repeated calls to `0x51520f0` stop on a zero output field (`0x4de077b..0x4de0790`), `0x4de0792..0x4de07a8` takes the transition only if the map's first qword equals `0x8000000000000000` and its unsigned qword `+0x18` is below 32. #6676 ties this latter field to tracker `+0x78`. At 32 or more, or when the first qword differs, this selected branch jumps to the normal return without these transition writes.

On the selected transition path, the caller saves map `+8` and `+0x10`, clears map `+8` and `+0x18`, constructs a temporary descriptor, and calls `0x5b86860` (`0x4de07ae..0x4de0815`). That helper reads temporary descriptor `+0x40`, computes `24*n` with a checked upper bound and uses an indirect allocation call for nonzero size; for zero it initializes the pointer to 8 and count to zero (`0x5b86870..0x5b868d1`). After the helper returns, the caller prepares a second descriptor, repeatedly calls `0x51dc470` until the output first qword is zero, then writes the constructed four-qword value back to the map (`0x4de081a..0x4de08d4`). The complete builder, iteration, allocation and exceptional semantics are outside this packet.

These operations support an inference of a small-representation transition, but do not prove preserved contents, ordering, count identity, successful allocation or runtime reachability. Valid descriptors, correct relocation, no interference and normal helper returns are assumptions. No checkpoint, state-root or component-completion claim is made.

## Reproduction

Run `python3 research/work-items/RE-017-node115-replay-map-small-transition/verify.py` to authenticate the target, check seven instruction anchors and three direct calls, and reject seven independent one-byte mutations. `windows.txt` is Apple LLVM objdump 21.0.0 `-d --x86-asm-syntax=intel` output; Python 3.11.15 was used. The captured target is not executed.
