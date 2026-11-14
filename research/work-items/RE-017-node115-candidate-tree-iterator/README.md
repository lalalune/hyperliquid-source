# RE-017: candidate tree-iterator return layout

Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. This static packet follows the alternate `0x51373b0` iterator boundary left open in #6618. No target code is executed.

## Selected observations

- `0x5b81970` calls `0x51373b0` at `0x5b819cf` for the first alternate-representation element and at `0x5b81b83` for subsequent elements. Both selected call sites test `rax` for null; on non-null return, they load 32 bytes from the pointer in `rax`. #6618 traces how those bytes are appended to the candidate-preparation output but does not enter the iterator.
- The selected iterator starts by checking its qword `+0x40`. A zero value returns `rax = 0`; a nonzero value is decremented and stored back before checking that the descriptor's low dword is `1`. Another tag branches to `0x51375ca`, which calls an indirect helper followed by `ud2`; the helper's semantics are outside this packet.
- The normal selected tree-shaped path reads a node length at `+0x482` and tracks an index. When advancing beyond a node, it follows a link at `+0x160` and reads a 16-bit field at `+0x480`. Its descent path follows links at `+0x488`, including an eight-link unrolled loop. These observed offsets do not by themselves prove balance, ordering or a source-language container type.
- At `0x5137581..0x51375a7`, the selected return path computes `rax = node + 32 * index` and `rdx = node + 0x168 + 72 * index`, then updates descriptor fields and returns. Thus the downstream caller's 32-byte projection comes from the selected node's 32-byte indexed region; it does not copy the separate address returned in `rdx`. “Key” and “value” are useful layout hypotheses, not proof that either region has a particular semantic identity.
- FDE interval `0x51373b0..0x51375d9` is retained as disassembly. It is an unwind range, not proof of all function boundaries, iterator invariants or runtime reachability.

The packet does not establish ordering, uniqueness, signer identity, authorization, root provenance or complete behavior of either iterator representation. Invalid pointers, allocator behavior and indirect-helper semantics remain out of scope. No acceptance gate is advanced.

## Reproduce

```sh
python3 research/work-items/RE-017-node115-candidate-tree-iterator/verify.py
readelf -wf artifacts/node/115/hl-node | rg 'pc=00000000051373b0'
/usr/bin/objdump -d --x86-asm-syntax=intel --start-address=0x51373b0 --stop-address=0x51375d9 artifacts/node/115/hl-node
```

The verifier authenticates the target SHA-256, checks twelve selected instruction anchors and both direct caller targets, and rejects twelve single-byte anchor mutations. It does not prove full CFG coverage, runtime behavior or all callers. #6618 is prior art for the downstream projection; this packet analyzes only its previously opaque alternate iterator boundary.
