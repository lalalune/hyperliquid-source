# RE-017: selected left-sibling rotation in replay tree (#115)

## Question and scope

For the low-count replay traversal branch documented in #6629, what does the previous-sibling helper do when called for a single entry at leaf depth? This extends #6625 and #6629, which leave the repair helper opaque. The active Linux x86-64 node #115 target is `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; addresses below are ELF virtual addresses. Main reference revision is `a8616af9432b8d8517b2af677880e117b7c28ef3`. No source code from the binary or unlicensed references is copied.

## Observations and interpretation

The caller builds a descriptor containing the parent, parent slot `j-1`, previous child, and current child (`0x4d2c130..0x4d2c159`). On its `c+s>=12` branch it calls `0x4c92630` with `n=1` (`0x4d2c1fd..0x4d2c207`). The helper occupies unwind FDE `[0x4c92630,0x4c92934)`.

Assume the descriptor denotes two valid leaves with left count `L>=1`, right count `R`, and `R+1<12`; memory is valid and the ELF's `memmove` and `memcpy` dynamic relocations resolve as named and return normally. On that selected path:

1. The helper stores `L-1` in the left count and `R+1` in the right count (`0x4c9263e..0x4c92687`).
2. It moves the right leaf's existing 8-byte and 12-byte fields one position right (`0x4c9268e..0x4c926d4`). The memcpy lengths in the subsequent bulk transfer are zero for `n=1` (`0x4c926da..0x4c92732`).
3. It replaces the parent separator at slot `j-1` with the left leaf's final 8-byte and 12-byte fields, then places the old separator in right slot zero (`0x4c92738..0x4c927a3`). Inference: this is a one-entry left-to-right rotation through the parent.
4. When both descriptor depth fields are zero, the branch at `0x4c927a7..0x4c927b0` and `0x4c9281f..0x4c92822` reaches the return without modifying child pointers. Mismatched depth fields reach a separate error path. Nonzero matching depth enters a child-pointer transfer and index-rewrite path, not claimed here.

The guard at `0x4c9264e` rejects `R+n>=12` and the subtraction at `0x4c9266b` rejects `L<n`. These are observations about control flow, not a runtime proof that all callers satisfy the preconditions. This packet does not establish the called error helper, concurrency behavior, ordering invariant, actual runtime path, or complete tree balance. It does not establish a checkpoint height, replay result, or state root.

## Reproduction and controls

From the repository root, run `python3 research/work-items/RE-017-node115-replay-left-rotation/verify.py`. It verifies the target digest, eight selected instruction anchors, the caller's direct target, and rejects eight independent one-byte anchor mutations. `body.txt` and `caller.txt` were generated with Apple LLVM objdump 21.0.0 using `-d --x86-asm-syntax=intel` and the address bounds in the filenames' contents; `relocations.txt` contains the relevant `readelf -rW` records. Python 3.11.15 was used. The verifier checks authenticated target bytes, not behavioral equivalence; no captured code is executed. No completion gate is advanced.
