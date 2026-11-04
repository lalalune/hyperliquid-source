# Evidence — RE-001-node115-lu-leaf-rebalance

## Claim

FDE `0x4d24790..0x4d24f68` in node #115 is the B-tree node
removal-and-rebalance primitive: it removes one key/value pair from
a node, rebalances against a sibling when the node underflows, and
cascades upward while ancestors underflow. Its third argument is a
flag-byte pointer that it sets to `1` exactly when the cascade
empties the root (tree height shrinks by one). The node `+0xe4` u16
is the node's index within its parent's children array.

## Method

Static disassembly only (`objdump -d -M intel`, `readelf -r` /
`readelf --debug-dump=frames-interp`). The node binary was never
executed. FDE bounds come from `.eh_frame` (readelf frames-interp:
`FDE cie=00000000 pc=0x4d24790..0x4d24f68`); the body/tail split
follows the single `ret` at `0x4d24a46`, with the tail reached by
jumps from the body (`0x4d248fc je 0x4d24f4f`,
`0x4d249fa jbe 0x4d24a47`) and from within the tail itself. All
counts below were recomputed by the verifier
(`tools/node115_lu_leaf_rebalance.py`), not copied from this file.

## Observations

| Site | Bytes / instruction | Reading |
| --- | --- | --- |
| `0x4d247ae` | `mov rbp,[rsi]` | node = loc[0] |
| `0x4d247b1` | `mov r15,[rsi+0x10]` | index = loc[0x10] |
| `0x4d247b5` | `movzx ebx,[rbp+0xe6]` | old count |
| `0x4d247f4` | `call r14` (GOT `0x64df568` = memmove) | keys shift left, `(old-1-index)*4` bytes |
| `0x4d24829` | `call r14` (memmove) | value slots shift left, `(old-1-index)*16` bytes |
| `0x4d24832` | `mov [rbp+0xe6],ax` | count = old − 1 |
| `0x4d2483e` | `cmp ax,4; ja 0x4d248db` | new count > 4 → output, no rebalance |
| `0x4d24848` | `mov rax,[rsi+0xb0]; je 0x4d248ea` | no parent → output, flag untouched |
| `0x4d2485c` | `movzx edx,[rsi+0xe4]` | child index read (entry sibling selection) |
| `0x4d2486f` | `mov rsi,[rax+rdx*8+0xe0]` | left sibling = children[index−1] |
| `0x4d248f4` | `cmp [rax+0xe6],0; je 0x4d24f4f` | index 0 → right sibling; zero-key parent → panic |
| `0x4d24902` | `mov rdx,[rax+0xf0]` | right sibling = children[1] |
| `0x4d248bb` / `0x4d2494e` | `cmp ebx,0xc; jae` | first-level merge gate: combined < 12 |
| `0x4d24967` | `call 0x4ca2500` | merge helper (direction in rdx) |
| `0x4d2497b` / `0x4d249ac` | `call 0x4c93c20` / `0x4c9b3b0`, `esi = 1` | first-level redistribute helpers |
| `0x4d24a65` | `call [0x64df4a0]` (→ `0x635de30`) | free merged-away node (r12) |
| `0x4d24a6b` / `0x4d24a7b` | `movzx eax,[rbx+0xe6]` / `movzx eax,ax` | current-node count into rax |
| `0x4d24a88` | `je 0x4d24eec` | parent null → root reached |
| `0x4d24eec` | `test rax,rax; jne 0x4d249fc` | root count nonzero → exit, flag untouched |
| `0x4d24ef5` / `0x4d24efa` | `mov rax,[rsp+0x50]; mov byte [rax],1` | sole flag write, on the root-empty path only |
| `0x4d24a95` | `movzx r12d,[rcx+0xe4]` | child index read (loop sibling selection) |
| `0x4d24bc8` | `mov [r14+0xe6],si` | sibling count updated in merge core |
| `0x4d24c08` | `mov [r14+r13*4+0xb8],r15d` | separator key appended to sibling |
| `0x4d24daa` | `dec word [rbx+0xe6]` | parent count decremented |
| `0x4d24d13`, `0x4d24e33` | `mov [child+0xe4],index` | single-step reparent loops |
| `0x4d24d4f`…, `0x4d24e6f`… | `mov [child+0xe4],index(+0..3)` | unrolled-by-4 reparent loops |
| `0x4d24f4f` | panic via `0x64df6b8`, msg `0x9133db`, len 123, loc `0x649a510` | `node.rs 1360:31`, "empty internal node" |
| `0x4d24f36` | panic via `0x64df730`, msg `0x913439`, len 40, loc `0x649a540` | `node.rs 1876:5`, "src.len() == dst.len()" |

## Caller chain (flag pointer)

Completion helper `0x4da86a0` zeroes `[rsp+0x7]`
(`0x4da86b7`), passes its address in `rdx` (`0x4da86c1`) to the
resolver `0x4d35b60` (`0x4da86c9`), which passes `rdx` through to
both leaf-op call sites (`0x4d35c75`, `0x4d35d5b`). After the
resolver returns, the completion helper tests the flag
(`0x4da86ea`) and, when set, promotes the old root's first child
(`[rax] = [rdi+0xe8]`, new root parent zeroed) and frees the old
root — the root-collapse handling the flag signals.

## Node capacity arithmetic (cross-check)

328-byte node, 11 keys max: value slots `[0,176)` (11 × 16),
parent `[176,184)`, keys `[184,228)` (11 × 4), child index
`[228,230)`, count `[230,232)`, children `[232,328)` (12 × 8).
Merge fits exactly when `old current + sibling ≤ 11` (first level;
the removal −1 and separator +1 cancel) and when `new current +
sibling + 1 ≤ 11` (upward loop, count already decremented) — hence
the `< 12` gates. Rebalance triggers at new count `≤ 4`.

## Negative checks performed

- Byte scan for direct `E8` callers of `0x4d24790` over all of
  `.text`: exactly 2 sites (`0x4d35c75`, `0x4d35d5b`).
- Relocation scan for GOT slots resolving to `0x4d24790`: none.
- Instruction-boundary check of the flag write: the only
  `mov byte [reg],1` to the flag pointer is at `0x4d24efa`; a raw
  `c6 00 01` byte pattern also occurs inside the displacement of
  `mov rcx,[r14+rax*8+0x100]` at `0x4d24ea8` and is not an
  instruction boundary — it is not counted.
- Claimed-body overlap against packets #183–#195: disjoint from
  every claimed FDE (see verifier).
- Upstream candidate directory absent (contents 404; 720-entry
  recursive tree, `truncated=false`); open-PR searches hit only
  #2302 (#195, the inviting prior) and unrelated #2167.
