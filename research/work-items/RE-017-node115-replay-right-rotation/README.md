# RE-017: selected right-sibling rotation in replay tree (#115)

## Question and scope

For the low-count replay traversal branch in #6629, determine what the next-sibling helper does when called for a single entry at leaf depth. This complements the previous-sibling case in #6666. The active Linux x86-64 node #115 target is `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; addresses are ELF virtual addresses. Main reference revision: `a8616af9432b8d8517b2af677880e117b7c28ef3`. No source from unlicensed references is used.

## Observations and interpretation

When the current node's parent index is zero and the parent count is nonzero, the caller takes the next child at `parent+0xf0`, builds a descriptor for current and next child and calls `0x4c98390` with `n=1` if the original current count plus next count is at least 12 (`0x4d2c183..0x4d2c21e`). The helper occupies unwind FDE `[0x4c98390,0x4c986eb)`.

Assume the descriptor contains two valid leaves, current count `L`, right count `R>=1`, `L+1<12`, valid nonoverlapping copy ranges, resolved ELF `memcpy`/`memmove` slots and normal returns. Then for `n=1`:

1. It sets the current count to `L+1` and next count to `R-1` (`0x4c9839e..0x4c983da`).
2. It takes the next leaf's first 8-byte and 12-byte fields, replaces the parent separator with them, and appends the previous separator at current index `L` (`0x4c983e1..0x4c98468`).
3. The bulk memcpy count for the remaining transferred fields is zero; memmove shifts the next leaf's `R-1` trailing fields left one place (`0x4c9846d..0x4c984e6`). Inference: this is a one-entry right-to-left rotation through the parent.
4. If both descriptor depth words are zero, `0x4c984ec` and `0x4c985e9` skip the child-pointer transfer and reach the return. Matching nonzero depths perform additional pointer operations, outside this claim; mismatched zero/nonzero depths take a separate error path.

The helper checks `L+n<12` and rejects subtraction underflow `R<n` before the field updates. The branches do not prove runtime preconditions or actual reachability. No claim is made about the error helper, all tree invariants, checkpoint height, replay output or state root.

## Reproduction and controls

Run `python3 research/work-items/RE-017-node115-replay-right-rotation/verify.py`. It authenticates the target, checks nine instruction anchors and the direct caller target, and rejects nine independent single-byte mutations. `caller.txt` and `body.txt` use Apple LLVM objdump 21.0.0 with `-d --x86-asm-syntax=intel`; `relocations.txt` contains relevant `readelf -rW` lines. Python 3.11.15 was used. Static anchor checks do not constitute native execution or behavioral equivalence. No completion gate is advanced.
