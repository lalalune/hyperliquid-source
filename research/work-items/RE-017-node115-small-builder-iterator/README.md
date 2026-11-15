# RE-017: small-map builder tree iterator (#115)

## Question and scope

PR #6686 traces the builder's output and stop conditions, but treats iterator `0x51dc470` as opaque. How does this selected iterator supply node and index pairs to the builder? Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; ELF virtual addresses. Main reference `a8616af9432b8d8517b2af677880e117b7c28ef3`; iterator FDE `[0x51dc470,0x51dc81a)`.

## Selected observations

The builder calls the iterator at `0x5b86976`, reads the returned node and index, and selects an 8-byte and 12-byte pair as described in #6686. For iterator tag 1, nonzero remaining qword at descriptor `+0x40`, nonnull current node and index below its 16-bit count at `+0xe6`, the iterator decrements the remaining qword and returns the original `(node,depth,index)` at output offsets `0`, `8`, and `0x10`. For depth zero, it leaves the same node and sets the input index to `i+1` (`0x51dc47e..0x51dc4c9`, `0x51dc6b8..0x51dc729`).

For a positive depth `d`, the selected internal path first addresses child `i+1` at `node+0xf0+8*i`, follows that pointer and then `d-1` pointers at `+0xe8` (with an eight-at-a-time loop), and sets the next descriptor to `(last_child,0,0)` while returning the original tuple (`0x51dc4cf..0x51dc514`, `0x51dc6c1..0x51dc729`). If the current index is exhausted, the separate ascent path follows the node's first qword, uses the 16-bit `+0xe4` field as a parent index and calls through `0x64df4a0` with depth-dependent sizes; it resumes when an ancestor index is below its count (`0x51dc654..0x51dc6b2`). The zero-remaining path clears the descriptor's first qword and has a separate selected chain cleanup (`0x51dc519..0x51dc59e`).

These observations assume valid, finite, depth-consistent nodes, correct relocation and normal calls. They do not prove complete traversal order, cleanup behavior, allocation semantics, actual zero-valued entries or live reachability. The inferred relationship to #6686's output is conditional; no checkpoint, state-root or gate-completion claim is made.

## Reproduction

Run `python3 research/work-items/RE-017-node115-small-builder-iterator/verify.py` to authenticate the target, check seven instruction anchors and one direct call, and reject seven single-byte mutations. `iterator.txt` and `caller.txt` use Apple LLVM objdump 21.0.0 `-d --x86-asm-syntax=intel`; `relocation.txt` uses `readelf -rW`. Python 3.11.15 was used. No target code is executed.
