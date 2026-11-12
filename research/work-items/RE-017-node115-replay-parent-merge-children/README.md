# RE-017: recursive merge internal children (#115)

## Question and scope

PR #6674 establishes the recursive inline merge but excludes its internal child-pointer transfer. This packet traces that branch and distinguishes it from the separate leaf-repair helper in #6672. Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; ELF virtual-address coordinates. Main reference `a8616af9432b8d8517b2af677880e117b7c28ef3`, FDE `[0x4c35400,0x4c35928)`.

## Observations

In the selected `<12` merge branch, the setups record the left count `L`, right count `R`, combined count `M=L+R+1`, surviving left node and discarded right node. After the field and parent updates in #6674, if the saved parent depth is at least two, `0x4c35785..0x4c357bd` checks `R+1 == M-L` and copies `R+1` pointers from the right child array at `+0xe8` into the left child array beginning at index `L+1`.

The remainder and four-at-a-time loops at `0x4c357c3..0x4c35879` write the left node to the first qword of each copied child and its new index to child `+0xe4`. The helper supplies size `0x148` to the subsequent indirect cleanup call; the shallow path instead supplies `0xe8`. The indirect callee's semantics are not established.

This interpretation assumes `L+R+1<12`, valid descriptors, child pointers and buffers, no alias interference, relocation of `0x64df508` to `memcpy`, and normal returns. It does not prove actual reachability, ordering invariants, complete recursive repair, checkpoint recovery, or state-root alignment. No completion gate is advanced.

## Reproduction

Run `python3 research/work-items/RE-017-node115-replay-parent-merge-children/verify.py` to authenticate the target and check six anchors and six independent single-byte mutations. `windows.txt` is Apple LLVM objdump 21.0.0 `-d --x86-asm-syntax=intel` output; `relocations.txt` uses `readelf -rW`. Python 3.11.15 was used. No target code is executed.
