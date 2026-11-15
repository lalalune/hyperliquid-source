# RE-017: selected small-map builder stop conditions (#115)

## Question and scope

PR #6685 establishes the post-traversal small-map transition but leaves the builder's content behavior open. Which selected entries does `0x5b86860` copy, and when does it stop copying? Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; ELF virtual addresses. Main reference `a8616af9432b8d8517b2af677880e117b7c28ef3`; builder FDE `[0x5b86860,0x5b86ae1)`.

## Observations

The selected transition calls this builder with a temporary iterator descriptor (#6685). It allocates space based on 24 times the descriptor's `+0x40` qword and repeatedly calls iterator `0x51dc470` (`0x5b86870..0x5b86976`). For a nonnull returned node and returned index `i`, it reads a 32-bit field at `node+0x60+12*i`. If that field is zero, it branches to the end of the copy loop. Otherwise it copies the qword at `node+8+8*i`, that dword, and the qword at `node+0x64+12*i` to offsets `0`, `8`, and `12` of the next 24-byte output slot, and advances the output length by one (`0x5b8697b..0x5b869b9`). The final four bytes of each slot are not written by these selected stores.

A null iterator result also exits the copy loop. After either exit, the builder stores the number copied, repeatedly calls the same iterator until its returned node is null, then returns the output descriptor (`0x5b869bb..0x5b869f7`). Thus, under valid pointers, sufficient allocation and normal iterator returns, a selected zero first dword stops copying even if later iterator results exist; the subsequent drain is not a second copy loop. This is a conditional control-flow observation, not a claim that such zero values are valid or reachable in a real node, that records are lost in production, or that any representation conversion is fully correct. Iterator internals, exceptions, allocation failures, checkpoint and state-root equivalence remain open. No completion gate is advanced.

## Reproduction

Run `python3 research/work-items/RE-017-node115-small-map-builder-stop/verify.py` to authenticate the target, check four anchors and three direct calls, and reject four independent one-byte mutations. `windows.txt` uses Apple LLVM objdump 21.0.0 `-d --x86-asm-syntax=intel`; `fde.txt` uses `readelf -wf`. Python 3.11.15 was used. The captured target is not executed.
