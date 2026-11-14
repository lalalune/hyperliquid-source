# RE-017: left-sibling internal child transfer (#115)

## Question and evidence

PR #6666 resolves the leaf-depth left rotation but explicitly excludes its nonzero-depth child transfer. This packet determines that distinct branch for `n=1`. Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Addresses are ELF virtual addresses; reference main is `a8616af9432b8d8517b2af677880e117b7c28ef3`. FDE `[0x4c92630,0x4c92934)`.

## Selected observations

Let `L` and `R` be the original left and right 16-bit counts. Under the caller's `n=1`, both depth words nonzero, `L>=1`, `R+1<12`, valid child arrays, successful nonoverlapping copy, resolved `memcpy`/`memmove` slots and normal returns:

- Following the field rotation documented in #6666, the helper moves the right node's `R+1` child pointers one slot right (`0x4c927b7..0x4c927dd`).
- It copies one child pointer from the left node's old child index `L` into right child slot zero (`0x4c927e3..0x4c927f9`). The index follows from the saved `L-1+1` at `0x4c926da..0x4c926de`.
- It walks all `R+2` right child slots and writes the right node into each child's first qword and the slot index into its 16-bit `+0xe4` field. The loop uses groups of four plus a remainder (`0x4c927ff..0x4c928d8`). Because the precondition bounds `R+1<12`, the loop's masking does not truncate this count.

Inference: the transferred child becomes the right node's first child and all shifted children are reparented/reindexed. Zero depths select the leaf branch, whereas mismatched zero/nonzero depth fields take an error path. This finding does not prove child ordering, full tree invariants, actual runtime reachability, checkpoint recovery or state-root alignment.

## Reproduce and controls

`python3 research/work-items/RE-017-node115-replay-left-child-reparent/verify.py` authenticates the target and verifies six anchors and six one-byte mutation controls. `windows.txt` uses Apple LLVM objdump 21.0.0 `-d --x86-asm-syntax=intel`; `relocations.txt` contains `readelf -rW` entries. Python 3.11.15 was used. Static checks do not execute target code; no gate is advanced.
