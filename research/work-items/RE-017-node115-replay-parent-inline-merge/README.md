# RE-017: recursive parent inline merge (#115)

## Question and scope

PR #6673 maps the recursive parent helper's rotation decision and leaves its lower-count inline merge unexplained. This packet traces that distinct path. Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; ELF virtual addresses. Reference main `a8616af9432b8d8517b2af677880e117b7c28ef3`; helper FDE `[0x4c35400,0x4c35928)`.

## Selected behavior

For a nonroot node of count `c<=4`, #6673 describes selection of a previous sibling if the child index is nonzero, otherwise a next sibling. For selected sibling count `s`, the `c+s+1<12` branch joins at `0x4c3559a`. The setup arranges the lower-index child as left and the other as right. Under valid node, parent and child descriptors, a valid separator index, sufficient storage, disjoint copy ranges, resolved `memmove`/`memcpy` slots and normal return:

1. The inline code stores the combined `left_count+right_count+1` in the left node, removes the parent separator by shifting its trailing 8-byte fields, and appends that separator and the right node's fields to the left node (`0x4c3559a..0x4c35612`).
2. It repeats the operation for the 12-byte fields and shifts the parent child-pointer tail (`0x4c35615..0x4c356b6`). It updates affected child parent/index metadata and decrements the parent's 16-bit count (`0x4c356b9..0x4c3576a`).
3. The depth-dependent child-array transfer begins at `0x4c35776`. On return from the indirect cleanup call at `0x4c35445`, the helper reloads the parent's count: if it remains at most four, processing continues from its own parent; if above four it returns one (`0x4c3544b..0x4c35458`).

These instructions support an interpretation of recursive upward repair following a merge. The indirect cleanup callee, complete child-transfer behavior, exceptions, concurrency and actual runtime reachability are not established. This result is separate from #6668's `0x4c9fa80` helper and does not establish checkpoint or state-root equivalence. No completion gate is advanced.

## Reproduction

Run `python3 research/work-items/RE-017-node115-replay-parent-inline-merge/verify.py`: it authenticates the target and verifies seven instruction anchors and seven one-byte mutation controls. `windows.txt` is Apple LLVM objdump 21.0.0 `-d --x86-asm-syntax=intel` output; `relocations.txt` uses `readelf -rW`. Python 3.11.15 was used. No target code is executed.
