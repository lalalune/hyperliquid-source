# RE-001-node115-lu-resolver

## Claim status: observation

This packet answers packet #198's (PR #2328) explicitly stated next
question: **the resolver `0x4d35b60` end to end — how does it consume
the leaf op's out48 (kept node, levels, edge index) to swap the
removed leaf key/value into an internal slot, and how do its two
leaf-op call sites (rightmost-leaf path vs remaining-levels `== 0`
path) each drive a different completion shape?**

The resolver is the B-tree internal-key deletion driver used by the
completion helper (`0x4da86a0`, #195). It takes a loc
`{node @+0, levels @+0x8, index @+0x10}` and an out buffer, and
returns the out pointer. The flag pointer it receives (`rdx`) is
forwarded untouched to the leaf op on both paths.

## The answer

**1. Remaining-levels `== 0` path: no swap, leaf-op output forwarded
verbatim.** When entry levels is `0` (`je 0x4d35d43` at `0x4d35b76`),
the resolver builds the loc `{node, 0, index}` on its own stack
(`0x4d35d43..0x4d35d50`), calls the leaf op at `0x4d35d5b`, and
returns the out pointer (`0x4d35d60..0x4d35d68`). The key to remove
is in the leaf itself, so the removed leaf key/value/flag IS the
completion payload — nothing is displaced.

**2. Rightmost-leaf path: the predecessor is removed, then swapped
into the slot.** When levels is nonzero, the resolver descends from
the internal node: first `children[index]` (`0x4d35b7c`), then
`levels - 1` further descents via `children[count]` (the rightmost
child) — a remainder loop (`0x4d35ba0`) plus an unrolled-by-8 loop
(`0x4d35bd0`); `levels == 1` skips the walk (`je 0x4d35c4e` at
`0x4d35b8a`). It then calls the leaf op at `0x4d35c75` with loc
`{rightmost leaf, 0, count - 1}` (`0x4d35c4e..0x4d35c66`) — the
rightmost key of the slot's left subtree, i.e. the predecessor.

**3. Out consumption and the climb fixup.** After the leaf-op call
the resolver reads out key (`0x4d35c7a`), value (`0x4d35c7f`),
flag byte (`0x4d35c84`), node (`0x4d35c8a`), levels
(`0x4d35c8f`), edge (`0x4d35c94`). If the edge is out of range for
the kept node (`cmp r8, [rax+0xe6]`, `jb 0x4d35ccc` at
`0x4d35c99..0x4d35ca3`), it climbs: child index from `+0xe4`
(`0x4d35cb0`), parent from `+0xb0` (`0x4d35cb8`), levels++
(`0x4d35cbf`), repeating while the child index is `>=` the parent
count (`0x4d35cc2..0x4d35cca`). A merge cascade can leave the
recorded edge past the end of the surviving node; the climb walks
to the ancestor whose count covers it, and the swap slot becomes
that ancestor's separator for the climbed-from child.

**4. The swap is a true exchange.** At `0x4d35ccc..0x4d35cf5` the
value-slot offset is `edge * 16` (`0x4d35ccf`); the old key is
read (`0x4d35cd3`) and the slot key overwritten with the removed
leaf key (`0x4d35cdb`); the old value (`0x4d35ce3`) and old flag
(`0x4d35ce7`) are read, then the slot value (`0x4d35ced`) and
slot flag (`0x4d35cf5`, removed flag masked to bit 0 at
`0x4d35cf1`) are overwritten with the removed pair. The OLD
internal slot contents become the resolver's output
(`0x4d35dc1..0x4d35dc7`).

**5. The two post-swap output shapes.** Leaf-op out levels is `0`
at both resolver call sites (see below), so the post-swap levels
counter equals the climb count exactly:
- No climb: output `{old key, old value, old flag, swap node, 0,
  edge + 1}` (`inc r8` at `0x4d35d69`).
- Climbed `k > 0` times: descend `k` steps from
  `children[edge + 1]` of the swap node, then `children[0]`s —
  remainder loop (`0x4d35d20`) plus unrolled-by-8 loop
  (`0x4d35d80`) — and output `{old key, old value, old flag,
  descended node, 0, 0}` (`0x4d35dc1..0x4d35dd7`).

**6. What the completion helper consumes.** The completion helper
calls the resolver exactly once (`0x4da86c9`) with out `rsp+0x48`,
the loc unchanged, and the flag pointer `rsp+0x7`
(`0x4da86bc..0x4da86c6`). It reads only out `+0x0..0x10`
(key+value, `0x4da86d8`) and out `+0x10` (flag qword,
`0x4da86ce`) into its 24-byte return (`0x4da8733..0x4da8741`).
The resolver's node/levels/edge outputs are written but never
read on this path. Hence the two completion shapes: levels
`== 0` returns the removed leaf pair; the rightmost path returns
the displaced internal pair.

## Scope

Included:

- The full FDE `0x4d35b60..0x4d35de4` (644 bytes; 134
  instructions: 106 body through the first `ret` at `0x4d35d68`
  + 28 tail through the second `ret` at `0x4d35de3`; 4 nops;
  2 calls, both to the leaf op `0x4d24790`).
- Entry signature `f(out: *mut [u8; 48], loc: *const Loc, flag:
  *mut u8)`; loc `{node @+0, levels @+0x8, index @+0x10}`;
  out48 `{key @+0, value @+0x8, flag @+0x10, node @+0x18,
  levels @+0x20, edge @+0x28}`.
- The pinned lemma: leaf-op out levels is `0` at both resolver
  call sites. The no-rebalance path copies loc levels
  (`0x4d24839`, `0x4d248db`); the helper paths copy frame levels,
  and the first-level frame is built from the same loc levels
  (#198: merge out `+0x8` = frame `+0x20`). The leaf op's
  `[rsp+0x38]` is written only at `0x4d248db` and `0x4d249cf`,
  so no cascade depth leaks into it.
- Census: exactly 1 direct E8 caller, the completion helper at
  `0x4da86c9` (bytes `e8 92 d4 f8 ff`); 0 GOT sites (no
  relocation addend `0x4d35b60` anywhere). In-resolver leaf-op
  calls verified: `0x4d35c75` (`e8 16 eb fe ff`) and `0x4d35d5b`
  (`e8 30 ea fe ff`), both targeting `0x4d24790`.
- Node layout reused from #196/#198 (328 bytes, capacity 11):
  value slots 16 bytes at `+16*i`, parent at `+0xb0`, u32 keys
  at `+0xb8 + 4*i`, child index u16 at `+0xe4`, key count u16
  at `+0xe6`, children at `+0xe8 + 8*i`.

Excluded:

- The leaf op, merge/redistribute helpers, flag helper, and
  completion helper internals (claimed by #195/#196/#198; only
  their call shapes and the completion helper's reads are cited
  here, not re-claimed as bytes).
- Any runtime behavior. Analysis is static only; the node binary
  was never executed.

## Reproduce

Worktree base: upstream main `8fd8db680ec4bfef40996e5616bce3d5156d0b86`
(node-115-only). Binary: `artifacts/node/115/hl-node`, 105,896,032 bytes,
SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
`.text` file offset = VA − 0x1000; `.data.rel.ro`/`.got` file offset =
VA − 0x2000; `.rodata` file offset = VA.
Instruction counts are strict mnemonic-line counts: objdump lines
with an address, a byte field, a tab, and a mnemonic.
Byte-continuation lines (address + bytes only) are excluded.

```sh
objdump -d -M intel --start-address=0x4d35b60 --stop-address=0x4d35de4 \
  artifacts/node/115/hl-node
python3 tools/node115_lu_resolver.py
python3 -m unittest tests.test_node115_lu_resolver -v
```

## What this changes about #196 and #198

- #196's "The resolver then swaps the removed leaf key/value into
  the internal slot (its own code, not claimed here)" is now
  claimed in full: the swap, the climb fixup, and both output
  shapes above.
- #196's loc description and #198's out48 labels stand, confirmed
  against the leaf-op output writes at `0x4d24a06..0x4d24a31`
  (out `+0x18` = node, `+0x20` = levels, `+0x28` = edge).
- Counting-method correction to #198: its instruction counts were
  taken with a loose regex that also matches objdump
  byte-continuation lines. Under the strict mnemonic-line count
  used here, #198's figures are merge 223 (not 225),
  redistribute-left 160 (not 161), redistribute-right 174 (not
  175). #198's bytes, addresses, census, and mechanism claims
  are unaffected.

## Limitations

- The resolver's node/edge outputs have no consumer in their only
  caller (the completion helper ignores them); this packet claims
  the computation, not a downstream use.
- The "predecessor" reading of the rightmost descent follows from
  the child-selection code (`children[index]`, then rightmost
  children, then last key); no runtime trace confirms it.
- No runtime behavior is claimed; the node binary was never executed.

## Next question

Census and decode the completion helper `0x4da86a0`'s direct
callers beyond the `0x4fb52e0` gate-release worked example: which
entry paths drive a tree removal through flag, resolver, and
completion, and what does each do with the 24-byte payload?
