# RE-001: the node #115 lu double slot-insert caller

## Question

Packet #219's next question: what does the FDE `0x6363660..0x63637e2`
do with its slot and node, why does it call the slot-insert helper
`0x63ac0d0` twice (`0x636370d`, `0x63637c7`), and how does its slot
relate to the allocator's pool slots?

## Answer

`0x6363660(unused, obj, node, ctx)` = (rdi, rsi, rdx, rcx) inserts the
node into the ctx's head/slot/anchor state machine and never drops it.
The first argument is never read. The second argument contributes one
u32 field, `[obj+0x13450]`, compared against the `.bss` word at
`0x650969c`. The node (rdx, kept in rbx) is compared by its
(`+0x20`, `+0x8`) key against the ctx's current head node at
`[ctx+0xc0]`. The ctx (rcx, kept in rbp) carries five fields used here:
`+0xc0` head, `+0xc8` slot, `+0xd8` anchor, `+0xa8` head-change counter,
`+0xb8` slot-insert counter.

- **Node key >= head key, or head NULL** — slot-insert the node into
  `ctx+0xc8` (call 1, `0x636370d`), bump `+0xb8`, return. The head is
  unchanged. This is the common path: the new node joins the slot chain
  and the head stays put.
- **Node key < head key** — the old head is evicted from `+0xc0`, the
  node becomes the new head (`+0xa8` bumped), and the old head goes to
  exactly one of two places, chosen by the tag bits
  `([head+0] >> 28) & 0x3ff`:
  - Tag zero: splice the old head into the `+0xd8`-anchored structure
    (inserted between the anchor and the anchor's `+0x30` successor;
    if the anchor is NULL the old head becomes the anchor), gated by
    the obj/global check below. Then `+0xa8++`, `[ctx+0xc0] = node`.
  - Tag nonzero: slot-insert the OLD head into `ctx+0xc8` (call 2,
    `0x63637c7` — note the second argument here is the old head, not
    the new node), bump `+0xb8`, then `+0xa8++`,
    `[ctx+0xc0] = node`.
- **Unlink-before-insert.** If `[ctx+0xd8] == node` on entry, the node
  is first unlinked from the anchor structure: if `[node+0x28] == node`
  (self-linked, sole element) the anchor is cleared to 0 and control
  goes to the head comparison; otherwise the anchor advances to
  `[node+0x28]` and the block-1 rotation runs before the comparison.
- **Gate.** The block-1 rotation and the path-B evict splice run only
  when `[obj+0x13450] >= [.bss 0x650969c]` (unsigned); otherwise they
  are skipped and control falls through to the head comparison /
  head replacement directly.

So the two calls are not duplicates: call 1 inserts the NEW node when
it does not displace the head; call 2 inserts the OLD head when the
new node displaces it and the old head carries nonzero tag bits. The
slot at `ctx+0xc8` is a 16-byte slot (chain head + second word) of
exactly the allocator pool-slot kind (#216/#217/#218): it is passed to
the same slot-insert helper with the same (slot, node) convention, and
its second word follows the same protocol the helper maintains. The
only difference is placement: this slot is embedded in a per-ctx
object instead of the pool's slot array.

## Entry and gate

- Entry `0x6363660`: `endbr64`, push rbp/rbx, `rbp = rcx` (ctx),
  `rbx = rdx` (node), `sub $0x8, %rsp`.
- `0x6363670`: `lea 0x650969c, %rax` (`.bss` word);
  `r8d = [rsi+0x13450]`; `edi = [rax]`; `jb 0x63636c2` skips block 1
  when `r8d < edi` (unsigned).
- `0x6363685`: `cmp 0xd8(%rcx), %rdx`; `je 0x63637a0` when
  `[ctx+0xd8] == node` (unlink path, below).

## Block 1: the successor-swap rotation

Runs only when the gate passes and `[ctx+0xd8] != node`. With
`p = [node+0x28]`, `s = [node+0x30]`, `r9 = [p+0x30]`:

- `[s+0x28] = r9`; `[p+0x30] = s`; `[node+0x30] = r9`;
  `[s+0x28] = p` (overwriting the first write); `[r9+0x28] = node`.
- Net: the node and `p` exchange their `+0x30` successors, with the
  `+0x28` backlinks repaired. `[node+0x28]` itself is untouched.
- Falls through to the head comparison.

## Head comparison

- `0x63636c2`: `rsi = [ctx+0xc0]` (head); `je 0x6363703` (insert path)
  when NULL.
- The `setb`/`sbb` signum idiom on `+0x20`, then `+0x8` as tiebreak —
  the same idiom #217/#219 use: result `+1` means the node key is
  smaller, `0` equal, `-1` greater.
- `cmp $0x1, %eax; je 0x6363728`: only the strictly-smaller outcome
  takes the evict path. Equal keys take the insert path.

## Insert path (call 1)

- `0x6363703`: `lea 0xc8(%rbp), %rdi` (slot), `mov %rbx, %rsi`
  (node), `call 0x63ac0d0` at `0x636370d`.
- `addq $1, 0xb8(%rbp)`; `ret` at `0x6363720`. The helper's return is
  ignored, consistent with #219's void return.

## Evict path

- `0x6363728`: `rdx = [head+0]`; `shr $0x1c`; `test $0x3ff`;
  `jne 0x63637c0` when the tag bits are nonzero (evict-to-slot).
- Tag zero, `0x636373b`: the obj/global gate again
  (`cmp %edi, %r8d; jb 0x6363788` skips the splice).
- `0x6363740`: `movups` self-pair into `[head+0x28]` (head, head);
  `r8 = [ctx+0xd8]`; if NULL, `[ctx+0xd8] = head` and done.
- Otherwise, with `t = [ctx+0xd8]`, `t_next = [t+0x30]`:
  `[head+0x28] = t`, `[t+0x30] = head`, `[head+0x30] = t_next`,
  `[t_next+0x28] = head`; `[ctx+0xd8]` stays `t`. The old head is
  inserted between the anchor and the anchor's successor.
- `0x6363788`: `addq $1, 0xa8(%rbp)`;
  `mov %rbx, 0xc0(%rbp)` (new head); `ret` at `0x636379d`.

## Evict-to-slot path (call 2)

- `0x63637c0`: `lea 0xc8(%rbp), %rdi` (slot); `rsi` is still the OLD
  head here — the call inserts the evicted head, not the new node.
  `call 0x63ac0d0` at `0x63637c7`.
- `addq $1, 0xb8(%rbp)`; `jmp 0x6363788` (head counter, new head,
  return, shared with the evict path).

## Unlink path (block 4)

- `0x63637a0`: `rdx = [node+0x28]`; `cmp %rdx, %rbx`;
  `jne 0x63637d6` when `[node+0x28] != node`.
- Self-linked: `movq $0, 0xd8(%rcx)` (anchor cleared);
  `jmp 0x63636c2` (head comparison, rotation skipped).
- Otherwise: `mov %rdx, 0xd8(%rcx)` (anchor advances to
  `[node+0x28]`); `jmp 0x6363692` (block-1 rotation, then comparison).

## Census

Whole-`.text` byte scan + per-site disassembly; `.rela.dyn` for GOT
(60,723 entries). This FDE `0x6363660`: 6 direct E8, 0 E9, 0 LEA,
0 GOT. E8: `0x63ea135`, `0x63ea495`, `0x63eaad3` (FDE starting
`0x63e9cd0`), `0x63eb134`, `0x63eb20a`, `0x63eb356` (FDE starting
`0x63ead50`). The caller FDEs' purposes are cited by address only,
not decoded here. The FDE itself makes exactly 2 calls, both to the
slot-insert helper; its E9 jumps are internal only
(`0x63637b4 -> 0x63636c2`, `0x63637dd -> 0x6363692`).

## Corrections to earlier packets

- **#219 confirmed.** The slot-insert helper is called with
  (slot, node) = (rdi, rsi) at both sites, and its return is ignored
  at both sites, consistent with its void return.
- **#219 confirmed.** The slot at `ctx+0xc8` is a 16-byte slot (chain
  head + second word) of exactly the allocator pool-slot kind, fed to
  the same helper.
- No bytes claimed by packets #183–#219 are re-claimed. All exhibits
  lie strictly inside this FDE; caller FDEs and the slot-insert FDE
  are cited by address only.

## Unresolved, stated not inferred

The exact invariant of the `+0x28`/`+0x30` structure (list versus
tree, and what the block-1 rotation preserves); the semantic identity
of the ctx object and of its `+0xc0` head versus `+0xd8` anchor; what
the obj `+0x13450` field and the `.bss` threshold count; what the
head tag bits (`>> 28) & 0x3ff`) encode; the purposes of the two
caller FDEs.

## Next question

Decode the FDE starting at `0x63e9cd0` end to end: what ctx object it
passes to `0x6363660`, what drives its three call sites
(`0x63ea135`, `0x63ea495`, `0x63eaad3`), and how its nodes reach the
head/slot/anchor state machine.

## Verification

- Static verifier `tools/node115_lu_dblinsert.py`: exit 0
  (5 excerpts, 226 bytes, 61 strict mnemonics, census
  6 E8 sites, MANIFEST 15/15).
- Unit tests `tests/test_node115_lu_dblinsert.py`: 9/9.
- `make verify`: exit 0 (29 manifests, 471 entries).
- `make catalogue-check`: exit 0.
- `make test`: 77 files attempted, 1 failed — the single
  failure is the pre-existing test_node115_catalogue Errno 18
  cross-device-link error, identical on pristine checkouts,
  not a packet regression; this packet's file [36/77]
  passes 9/9.
- Target: node #115, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (105,896,032 bytes), upstream main `8fd8db6`
  (fetch-confirmed unmoved before analysis).
- No bytes claimed by packets #183–#219 are
  re-claimed; earlier bytes are cited by address
  only. No execution of the node binary at any
  point.

## Files (16)

- `research/work-items/RE-001-node115-lu-dblinsert/README.md`
- `research/work-items/RE-001-node115-lu-dblinsert/EVIDENCE.md`
- `research/work-items/RE-001-node115-lu-dblinsert/records.json`
- `research/work-items/RE-001-node115-lu-dblinsert/MANIFEST.sha256`
- `research/work-items/RE-001-node115-lu-dblinsert/di_entry.hex`
- `research/work-items/RE-001-node115-lu-dblinsert/di_entry.objdump.txt`
- `research/work-items/RE-001-node115-lu-dblinsert/di_cmp.hex`
- `research/work-items/RE-001-node115-lu-dblinsert/di_cmp.objdump.txt`
- `research/work-items/RE-001-node115-lu-dblinsert/di_insert.hex`
- `research/work-items/RE-001-node115-lu-dblinsert/di_insert.objdump.txt`
- `research/work-items/RE-001-node115-lu-dblinsert/di_evict.hex`
- `research/work-items/RE-001-node115-lu-dblinsert/di_evict.objdump.txt`
- `research/work-items/RE-001-node115-lu-dblinsert/di_call2.hex`
- `research/work-items/RE-001-node115-lu-dblinsert/di_call2.objdump.txt`
- `tools/node115_lu_dblinsert.py`
- `tests/test_node115_lu_dblinsert.py`
