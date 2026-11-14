# RE-017: selected tree pending removal on missing digest (#115)

## Question and scope

PR #6691 connects a missing digest to removal from a flat pending representation. What happens on the separate sentinel-tree representation? Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; ELF virtual addresses; main reference `a8616af9432b8d8517b2af677880e117b7c28ef3`.

## Conditional path

Assume the selected tree traversal has a valid pending record, its primary timer comparison reaches extraction, and the tracker's digest lookup structure at `+0x18` is sentinel `0x8000000000000000` with null root at `+0x20`. As in #6691, `0x5377df0` writes result sentinel `0x8000000000000001`. The tree callback compares that sentinel at `0x51525c0..0x51525c9` and branches directly to the common removal tail, bypassing the row-building path.

The selected caller in #6676 binds traversal descriptor `+8` to pending-map `+0x18`, and the tail decrements that pointed-to qword before passing a selected node/depth/index descriptor to `0x4d31c60` (`0x51527e9..0x5152821`). Under the valid-descriptor, nonzero-count, no-alias and normal-return assumptions, the pending counter therefore decreases by one while no digest row is appended on this branch. #6625 separately maps the leaf-depth removal helper; its balancing and exceptional paths are not re-proved here.

This is a selected, conditional static path, not proof that such a tracker state is valid or reached in real replay, that later data cannot recover it, or that any security impact occurs. It does not establish checkpoint-height identity, state-root equivalence or a component gate.

## Reproduction

Run `python3 research/work-items/RE-017-node115-tree-missing-digest-removal/verify.py` to authenticate the target, verify five instruction anchors and three direct calls, and reject five independent one-byte mutations. `windows.txt` uses Apple LLVM objdump 21.0.0 `-d --x86-asm-syntax=intel`; Python 3.11.15 was used. The captured target is not executed.
