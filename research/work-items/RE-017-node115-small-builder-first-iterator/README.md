# RE-017: small-map iterator initial descent (#115)

## Question and scope

PR #6687 maps the builder iterator's initialized node cases but leaves its initial null-node path open. How is its first selected node chosen? Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; ELF virtual addresses; main reference `a8616af9432b8d8517b2af677880e117b7c28ef3`. Iterator FDE `[0x51dc470,0x51dc81a)`.

## Selected observations

For descriptor tag 1, nonzero remaining qword `+0x40` and null current node at `+8`, the iterator decrements remaining first and enters `0x51dc5ab`. It reads a starting node from descriptor `+0x10` and a qword `h` from `+0x18`. Under valid pointer and finite-depth assumptions, it follows the qword at node `+0xe8` exactly `h` times; the code uses a remainder loop and an eight-link unrolled loop (`0x51dc5b7..0x51dc62c`). Zero `h` selects the starting node directly.

At `0x51dc62e..0x51dc644` it sets tag 1, stores the reached node at `+8`, zeros descriptor `+0x10` and `+0x18`, and reads the reached node's 16-bit count at `+0xe6`. If the count is nonzero, it joins #6687's zero-depth successful path with index zero: the returned node/index is `(reached,0)` and the descriptor's next index becomes one. If count is zero, control enters a different ascent case, not established here. This supports an interpretation of finding the first entry through leftmost child links, but does not establish ordering, root provenance, valid runtime inputs, checkpoint restoration or state-root equivalence. No completion gate changes.

## Reproduction

Run `python3 research/work-items/RE-017-node115-small-builder-first-iterator/verify.py` to authenticate the target and check five instruction anchors and five independent one-byte mutations. `windows.txt` uses Apple LLVM objdump 21.0.0 `-d --x86-asm-syntax=intel`; Python 3.11.15 was used. No captured code is executed.
