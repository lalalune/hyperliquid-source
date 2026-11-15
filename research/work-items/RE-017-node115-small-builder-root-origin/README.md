# RE-017: small-map builder initial root origin (#115)

## Question and scope

PR #6689 identifies the iterator's first-node descent but leaves the caller-supplied starting node and depth as inputs. On #6685's selected small-map transition, where do those inputs come from? Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; ELF virtual addresses; main reference `a8616af9432b8d8517b2af677880e117b7c28ef3`.

## Observations

After the tree traversal, `0x4de0792..0x4de07a8` selects this transition only for first map qword `0x8000000000000000` and unsigned map `+0x18` below 32. It reads the map's qwords `+8`, `+0x10` and `+0x18`, and clears `+8` and `+0x18`. When the original `+8` is nonzero, it constructs a temporary descriptor at `rsp+0x28`: tag 1 at `+0`, zero current node at `+8`, original map `+8` at `+0x10`, original map `+0x10` at `+0x18`, and the original map `+0x18` at `+0x40` (`0x4de07ae..0x4de0806`). It then passes that descriptor to `0x5b86860`.

The builder copies the descriptor, including its `+0x40` qword, to a local iterator and calls `0x51dc470` (`0x5b868da..0x5b86976`). For a positive original map `+0x18`, the iterator takes the tag-1, null-current-node case. By #6689, the first candidate starts at original map `+8` and follows `original map[+0x10]` links through each node's `+0xe8` field. If the reached node has positive count, its index-zero record is returned. For a null original `+8`, the caller instead constructs tag zero and remaining zero; no equivalent first-node claim is made.

This is conditional dataflow: the map fields are observed qwords, not proven checkpoint height or authenticated state. Valid descriptors, finite depth, nonnull traversed links, successful allocation, absence of aliases and normal calls are assumptions. No runtime reachability, ordering, complete conversion, checkpoint recovery or state-root equivalence is established. No gate is advanced.

## Reproduction

Run `python3 research/work-items/RE-017-node115-small-builder-root-origin/verify.py` to authenticate the target, verify five instruction anchors and two direct calls, and reject five single-byte mutations. `windows.txt` uses Apple LLVM objdump 21.0.0 `-d --x86-asm-syntax=intel`; Python 3.11.15 was used. The target is not executed.
