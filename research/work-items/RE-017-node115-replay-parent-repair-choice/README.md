# RE-017: parent repair borrow choice (#115)

## Question and scope

PR #6669 identifies the empty-root return from the recursive parent-repair helper but leaves its nonroot decisions open. When does the selected helper choose sibling rotation, and how many fields does it request? Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; ELF virtual-address coordinates. Main reference `a8616af9432b8d8517b2af677880e117b7c28ef3`; helper FDE `[0x4c35400,0x4c35928)`.

## Observations

`0x4c35411` reads a 16-bit count `c`. If `c>4`, the helper returns one; otherwise it loads the node's parent and child index (`0x4c3544b..0x4c35479`). For a nonzero index, it selects the previous child of the parent; for index zero, it selects the next child and takes an exceptional branch if the parent count is zero (`0x4c35484`, `0x4c35510..0x4c35520`). Each path reads that sibling's count `s` and compares `c+s+1` to 12.

If `c+s+1>=12`, the previous-sibling path calls `0x4c92630` and the next-sibling path calls `0x4c98390`; both receive `n=5-c` (`0x4c358ac..0x4c358d8`). For `0<=c<=4`, this requests one through five entries. Under valid-descriptor and normal-return assumptions, the count update instructions documented in #6666 and #6667 imply a new current count of five; the comparison implies `s>=11-c`, so the requested `5-c` does not exceed that sibling count. These are arithmetic deductions from selected instructions, not proof of runtime invariants. The `<12` side proceeds through an inline merge path whose full behavior is not characterized here. A null parent instead follows the root return cases in #6669.

The packet does not show live reachability, pointer validity, all recursive iterations, helper correctness, checkpoint recovery or root alignment. Completion gates remain false.

## Reproduction

Run `python3 research/work-items/RE-017-node115-replay-parent-repair-choice/verify.py` to authenticate the target and check seven instruction anchors, two direct targets and seven independent single-byte mutation controls. `windows.txt` is Apple LLVM objdump 21.0.0 `-d --x86-asm-syntax=intel` output. Python 3.11.15 was used; no target code is executed.
