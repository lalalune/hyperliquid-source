# RE-017: flat-callback remap iterator inputs (#115)

## Question and scope

PR #6679 follows the flat callback into `0x5b7a830` but leaves this helper opaque. How does it supply the common registry-remap loop already documented at `0x5b7a9a0` in #5157? Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; ELF virtual addresses. Main reference `a8616af9432b8d8517b2af677880e117b7c28ef3`. The helper's FDE is `[0x5b7a830,0x5b7b0d5)`; `0x5b7a9a0` is an interior join in that range, not a separately asserted function entry.

## Observations

The callback constructs an input descriptor at `rsp+0x10` and calls `0x5b7a830` at `0x57d4968`. For descriptor tag 2 and nonzero remaining qword `+0x20`, the helper reads capacity `+8`, base `+0x10`, and head `+0x18`, advances the head with a single capacity wrap, decrements the remaining qword and loads a `0x68`-byte row from the old head. It places the first 32 bytes at local `rsp+0x90` and the following 72 bytes at `rsp+0xb0`, then jumps to `0x5b7a9a0` (`0x5b7a870..0x5b7a916`).

For other tags it calls `0x51dfbc0` on the input descriptor. On that helper's nonnull result, it reads a node and index, loads 32 bytes from `node+32*index`, and 72 bytes from `node+0x168+72*index` into the same two local buffers, then falls through to the same join (`0x5b7a920..0x5b7a9a0`). The helper's empty and exceptional outcomes remain outside this claim. At the join, the first 32 bytes are copied to a lookup input and passed through relocation slot `0x64e5068`; a `0x1a2` result is required to proceed, otherwise the loop continues (`0x5b7a9a0..0x5b7a9e7`). #5157 documents the downstream selected lookup result and remap.

Under valid descriptor, ring and node layouts, correctly resolved relocations and normal calls, the two selected input representations therefore supply the same local field widths to the common remap. This does not prove either representation's runtime reachability, iteration ordering, all elements, lookup authentication, checkpoint recovery or state-root equivalence. No completion gate changes.

## Reproduction

Run `python3 research/work-items/RE-017-node115-flat-remap-iterator/verify.py` to authenticate the target and check five anchors, two direct calls and five independent one-byte mutations. `windows.txt` uses Apple LLVM objdump 21.0.0 with `-d --x86-asm-syntax=intel`; `relocation.txt` uses `readelf -rW`. Python 3.11.15 was used; no target code is executed.
