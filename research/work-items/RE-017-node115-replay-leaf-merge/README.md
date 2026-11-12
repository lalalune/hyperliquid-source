# RE-017: selected replay tree leaf merge (#115)

## Question and evidence

For #6629's low-count replay tree dispatch, determine what the shared helper at `0x4c9fa80` does on the leaf case. This covers the complementary low-sum case to the two leaf rotations in #6666 and #6667. Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; coordinates are ELF virtual addresses. Reference main revision: `a8616af9432b8d8517b2af677880e117b7c28ef3`. The helper's unwind FDE is `[0x4c9fa80,0x4c9fe85)`.

## Selected behavior

At the caller, if the original current count plus sibling count is below 12, it calls this helper (`0x4d2c1f6`) with a side flag identifying which original child supplied the selected record. The helper rejects a merged count `L+R+1>=12` and an out-of-range supplied index before changing the arrays (`0x4c9fa8e..0x4c9face`). Here `L` and `R` are the counts of the left and right descriptor children, after the caller's deletion.

Assuming valid leaf descriptors, a valid parent separator index `j`, nonoverlapping node storage, sufficient capacity, resolved `memmove`/`memcpy` relocations, normal calls and parent count greater than zero, the helper:

- Sets the left count to `L+R+1` and removes parent field `j` by shifting later 8-byte fields left. It writes the removed field into left slot `L` and copies all `R` right fields after it (`0x4c9fb18..0x4c9fb7e`).
- Performs the same operation for the 12-byte fields (`0x4c9fb84..0x4c9fc01`). This supports the inference that the left and right sequences are combined around their parent separator.
- Shifts the parent child-pointer tail left, repairs the affected parent/index links, and decrements the parent 16-bit count (`0x4c9fc07..0x4c9fcf3`).
- With descriptor parent depth below two, skips the deeper child-pointer transfer, calls slot `0x64df4a0` with the right node and size `0xe8`, and returns a descriptor based on the left node and adjusted index (`0x4c9fcf3..0x4c9fe27`). The detailed semantics of that indirect callee are not asserted.

The side flag changes the returned index; it does not alter the sequence construction described above. These are conditional static observations, not evidence of actual execution, allocator correctness, complete tree invariants, checkpoint height, or state-root alignment. Non-leaf transfer and exceptional branches remain open.

## Reproduction and controls

Run `python3 research/work-items/RE-017-node115-replay-leaf-merge/verify.py` from the repository root. It authenticates the target, checks eight instruction anchors and the direct caller target, and rejects eight independent one-byte mutations. `caller.txt` and `body.txt` use Apple LLVM objdump 21.0.0 with `-d --x86-asm-syntax=intel`; `relocations.txt` contains relevant `readelf -rW` lines. Python 3.11.15 was used. No captured code is executed and no completion gate is advanced.
