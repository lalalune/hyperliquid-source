# RE-017: right-sibling internal child transfer (#115)

## Question and evidence

PR #6667 resolves the leaf-depth right rotation but excludes its nonzero-depth child transfer. This packet determines that branch for `n=1`, complementing #6670. Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Addresses are ELF virtual addresses; reference main `a8616af9432b8d8517b2af677880e117b7c28ef3`. FDE `[0x4c98390,0x4c986eb)`.

## Selected observations

Let `L` and `R` be original current and next-node counts. Assume `n=1`, both depth words nonzero, `R>=1`, `L+1<12`, valid child pointers and arrays, successful nonoverlapping copy, correctly resolved `memcpy`/`memmove` slots and normal returns. Following #6667's field rotation, `0x4c98504..0x4c98527` copies one child pointer from next-node child slot zero to current-node child slot `L+1`. Then `0x4c9852d..0x4c98546` shifts the next node's `R` remaining child pointers one position left.

The helper writes the current node into the moved child's first qword and `L+1` into its 16-bit `+0xe4` field (`0x4c9854c..0x4c98557`). The later loop rewrites each of the remaining `R` next-node children with that node as parent and its new slot index (`0x4c985cf..0x4c986a8`), using groups of four and a remainder. Inference: this is the child-pointer part of the right-to-left internal rotation. At zero depth it follows the separate leaf path; mismatched zero/nonzero depth fields reach an error path.

This is conditional static analysis. It does not prove ordering invariants, runtime reachability, safety under aliases, full balancing, checkpoint recovery or state-root equivalence. No completion gate is advanced.

## Reproduce and controls

Run `python3 research/work-items/RE-017-node115-replay-right-child-reparent/verify.py` to authenticate the target and verify seven anchors and seven independent single-byte mutation controls. `windows.txt` is Apple LLVM objdump 21.0.0 `-d --x86-asm-syntax=intel` output; `relocations.txt` contains `readelf -rW` entries. Python 3.11.15 was used. The target is not executed.
