# RE-001: the node #115 lu collect sibling — table, remove, gate, rotate

## Question

Packet #221's next question: what does the collect sibling `0x6363560`
do end to end — what it does with (unused, obj, item, ctx), how it
differs from `0x6363660`'s head/slot/anchor state machine (#220), and
what consumes the output array the ctx feeder appends to at `0x63eab9e`
/ `0x63eac11` / `0x63eacf9`?

## Answer

`0x6363560(unused, obj, item, ctx)` = (rdi, rsi, rdx, rcx) is the
removal counterpart of #220's insertion state machine. It never
inserts anything. The first argument is never read. The second
contributes exactly one field, `[obj+0x13450]`, for the gate. The
item (rdx) is dispatched by a per-key-class table: one branch removes
it from the ctx's slot chain, the other runs a gated rotation (or an
anchor unlink) and returns. Every path decrements the ctx `+0xb0`
counter; only the slot-remove path also decrements `+0xb8`. The
function makes exactly one call, to the slot-remove helper
`0x63acb40`, and never calls the slot-insert helper `0x63ac0d0`.

Signature evidence: entry is `endbr64`, `push %rbx`,
`mov %rcx, %rbx` — rcx becomes the ctx for every field access. No
instruction in the FDE reads rdi before it is overwritten (rdi is
written only as the first argument of the `0x63acb40` call). rsi is
read only at the gate (`cmp %r11d, 0x13450(%rsi)`).

## Entry and ctx layout

- FDE `0x6363560..0x636365a` (250 bytes), 3 `ret` sites
  (`0x63635b5`, `0x6363615`, `0x6363634`), 2 unconditional jumps,
  both targeting inside the FDE (`0x636364c -> 0x63635ac`,
  `0x6363658 -> 0x63635dc`).
- Ctx fields used, all via rbx: `+0xc0` head, `+0xc8` slot,
  `+0xd8` anchor, `+0xb0` counter, `+0xb8` slot-membership counter.
  These are the same five fields #220 documents; `+0xa8` (head-change
  counter) is never touched here.
- Node words used: `+0x0` (key-class byte source), `+0x28` link pair
  member, `+0x30` chain link. The (`+0x20`, `+0x8`) sort key is not
  compared here — the key comparison lives inside the callees.

## The dispatch: head first, then the table

- Head check (`0x6363568`): `cmp 0xc0(%rcx), %rdx`;
  `je 0x6363620` when the item IS the head.
- **Head-clear path** (`0x6363620`): `[ctx+0xc0] = 0`,
  `[ctx+0xb0]--`, return. No slot call, no anchor handling, and —
  unlike #220's head replacement — no `+0xa8` bump. Clearing the head
  is not counted as a head change.
- Otherwise the table select runs: `rax = [item]`;
  `ecx = ([item] >> 20) & 0xff` (`shr $0x14` then `movzbl %al`);
  `r9 = 0x6711b40 + ecx * 40` (`lea (%rcx,%rcx,4)` then
  `lea (%r8,%rdi,8)` with `r8 = 0x6711b40`). The table is a `.bss`
  array of 40-byte entries, indexed by key byte.
- `cmpl $0x1, 0x10(%r9)`; `je 0x63635c0` takes the gate path when the
  entry's `+0x10` word equals 1; any other value falls through to the
  slot-remove path. 24 LEA sites across `.text` reference the table
  base `0x6711b40`, including this FDE's — the table is shared
  infrastructure, not private to this function.

## The slot-remove path

- Taken when the table entry's `+0x10` word is not 1.
- `lea 0xc8(%rbx), %rdi` (slot), `mov %rdx, %rsi` (item),
  `call 0x63acb40` at `0x636359f` — the same (slot, node) convention
  #219's slot-insert helper uses, but a different helper: its FDE is
  `0x63acb40..0x63ad582` (cited by address only), its head walks the
  slot chain with the same (`+0x20`, `+0x8`) signum idiom and zeroes
  `+0x28` pairs (`movups %xmm0` stores). Its other callers are
  `0x6363a6f` and `0x63b0847` (addresses only).
- Then `[ctx+0xb8]--`, `[ctx+0xb0]--` (fall-through into the shared
  tail at `0x63635ac`), return. This is the only path that touches
  `+0xb8`, pairing with #220's `+0xb8++` on slot-insert: `+0xb8`
  counts slot-chain membership.

## The gate path

- Taken when the table entry's `+0x10` word equals 1.
- `r11d = [.bss 0x650969c]`; `cmp %r11d, 0x13450(%rsi)`;
  `jb 0x63635ac` skips everything (only `[ctx+0xb0]--`, return) when
  `[obj+0x13450]` is unsigned below the global word. Same gate, same
  direction as #220 — and the same obj field.
- When the gate passes, `cmp 0xd8(%rbx), %rdx`; `je 0x6363638`
  takes the anchor path when the item IS the anchor; otherwise the
  rotation block runs.

## The rotation block

- With `p = [item+0x28]`, `s = [item+0x30]`,
  `p_next = [p+0x30]`, in order: `[s+0x28] = p_next`;
  `[p+0x30] = s`; `[item+0x30] = p_next`;
  `[p+0x28] = s`; `[p_next+0x28] = item`.
  `[item+0x28]` itself is untouched.
- Net: the item and `p` exchange their `+0x30` successors, with
  backlinks repaired. This is the same successor-exchange shape as
  #220's block-1 rotation, but the backlink writes differ: here
  `[s+0x28]` keeps `p_next` (in #220 it is overwritten to `p`) and
  `[p+0x28]` is set to `s` (in #220 it is untouched). The two
  rotations are related, not identical.
- Then `[ctx+0xb0]--`, return. No head comparison follows, no insert
  follows — the rotation is terminal here, whereas in #220 it runs
  before the head comparison.

## The anchor path

- `rsi = [item+0x28]`; `cmp %rsi, %rdx`.
- Self-linked (`[item+0x28] == item`, sole element):
  `[ctx+0xd8] = 0`, then the shared tail (`[ctx+0xb0]--`, return).
- Otherwise: `[ctx+0xd8] = [item+0x28]` (the anchor advances to the
  item's `+0x28` link), then `jmp 0x63635dc` into the rotation block
  above, then `[ctx+0xb0]--`, return.
- This mirrors #220's unlink-before-insert (same self-link test, same
  advance-or-clear), but as a terminal path: there is no subsequent
  head comparison or insert.

## Counters, stated as observed

- `+0xb0` is decremented on every exit path (all five paths reach a
  `subq $0x1, 0xb0(%rbx)`). It behaves as a per-ctx item count that
  every collect removes one from.
- `+0xb8` is decremented only on the slot-remove path. Paired with
  #220's increments on slot-insert, it behaves as a slot-membership
  count.
- `+0xa8` is never written here. Head clearing does not count as a
  head change; only #220's head replacement bumps `+0xa8`.
- The exact semantic identities of `+0xb0` / `+0xb8` beyond these
  increment/decrement pairings are not established here.

## The output array and its consumer

- The feeder (#221) appends the item to its output array immediately
  after each collect call: at the first site, `call 0x6363560` at
  `0x63eab9e` is followed by the store `mov %rdx, (%r11,%r10,8)` at
  `0x63eabc2` (array at `-0xc0(%rbp)`, count at `-0x70(%rbp)`).
  Collect runs first, then the item is appended — collect's removals
  from the slot/head/anchor structures do not remove the item from
  the feeder's output list.
- The consumer is the feeder's own final sweep at `0x63ea778`, which
  calls the finalizer `0x63612b0` (ctx, table value, item) once per
  collected item at 7 sites (`0x63ea7f3`, `0x63ea81d`, `0x63ea847`,
  `0x63ea885`, `0x63ea8aa`, `0x63ea8ce`, `0x63ea8f2`). The sweep and
  the finalizer are cited by address only; the finalizer's internals
  are not decoded here, and the array's allocation site is not
  established here.

## Census

Whole-`.text` byte scan + per-site disassembly; `.rela.dyn` for GOT
(60,723 entries). Collect helper `0x6363560`: 6 direct E8, 0 GOT.
E8: `0x63eab9e`, `0x63eac11`, `0x63eacf9` (feeder FDE
`0x63e9cd0..0x63ead50`, #221), and `0x63eb656`, `0x63eb6c9`,
`0x63eb74c` (adjacent FDE `0x63ead50..0x63eb79f`, not decoded here;
all three restore (rdi, rsi) from the frame and pass ctx in r12).
The FDE itself makes 1 direct E8 call (`0x63acb40`), 0 to itself.

## Corrections to earlier packets

- **#221 confirmed.** The three feeder collect sites pass
  (ctx, obj, item, shard-ctx); the feeder appends the item to its
  output array immediately after each call; the final sweep calls
  `0x63612b0` at 7 sites.
- **#220 confirmed.** Same ctx layout, same obj/global gate and
  direction, same anchor self-link rule, same
  (unused, obj, item, ctx) tuple shape.
- **#220 refined.** The rotation is not byte-identical to #220
  block 1: `[s+0x28]` keeps `p_next` here versus `p` in #220, and
  `[p+0x28]` is set to `s` here versus untouched in #220.
- **#219 confirmed.** The slot-insert helper is never called from
  this FDE; the ctx `+0xc8` slot is passed to the remove helper
  with the same (slot, node) convention.
- No bytes claimed by packets #183–#221 are re-claimed. All exhibits
  lie strictly inside the collect FDE; the feeder, the second caller
  FDE, the remove helper, and the finalizer are cited by address
  only.

## Unresolved, stated not inferred

What populates the `.bss` table at `0x6711b40` and what its `+0x10`
word equal to 1 means; the exact semantic identities of the ctx
`+0xb0` / `+0xb8` counters beyond their observed pairings; the
purpose of the second caller FDE `0x63ead50..0x63eb79f`; internals
of the remove helper `0x63acb40` beyond its head behaviour and of
the finalizer `0x63612b0`; what allocates the feeder's output array.

## Next question

Decode the slot-remove helper `0x63acb40` end to end: how it unlinks
a node from the slot chain, how it uses the (`+0x20`, `+0x8`) key
idiom to find the node, what it does with the node's `+0x28` pair
and `+0x30` link on removal, and what its three callers
(`0x636359f`, `0x6363a6f`, `0x63b0847`) share.

## Verification

- Static verifier `tools/node115_lu_collect.py`: exit 0
  (5 excerpts, 206 bytes, 48 strict mnemonics, census
  6 E8 sites, MANIFEST 15/15).
- Unit tests `tests/test_node115_lu_collect.py`: 10/10.
- `make verify`: exit 0 (29 manifests, 471 entries).
- `make catalogue-check`: exit 0.
- `make test`: 77 files attempted, 1 failed — the single
  failure is the pre-existing test_node115_catalogue Errno 18
  cross-device-link error, identical on pristine checkouts,
  not a packet regression; this packet's file [36/77]
  passes 10/10.
- Target: node #115, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (105,896,032 bytes), upstream main `8fd8db6`
  (fetch-confirmed unmoved before analysis).
- No bytes claimed by packets #183–#221 are
  re-claimed; earlier bytes are cited by address
  only. No execution of the node binary at any
  point.

## Files (16)

- `research/work-items/RE-001-node115-lu-collect/README.md`
- `research/work-items/RE-001-node115-lu-collect/EVIDENCE.md`
- `research/work-items/RE-001-node115-lu-collect/records.json`
- `research/work-items/RE-001-node115-lu-collect/MANIFEST.sha256`
- `research/work-items/RE-001-node115-lu-collect/cs_entry.hex`
- `research/work-items/RE-001-node115-lu-collect/cs_entry.objdump.txt`
- `research/work-items/RE-001-node115-lu-collect/cs_table.hex`
- `research/work-items/RE-001-node115-lu-collect/cs_table.objdump.txt`
- `research/work-items/RE-001-node115-lu-collect/cs_remove.hex`
- `research/work-items/RE-001-node115-lu-collect/cs_remove.objdump.txt`
- `research/work-items/RE-001-node115-lu-collect/cs_gate_rot.hex`
- `research/work-items/RE-001-node115-lu-collect/cs_gate_rot.objdump.txt`
- `research/work-items/RE-001-node115-lu-collect/cs_anchor.hex`
- `research/work-items/RE-001-node115-lu-collect/cs_anchor.objdump.txt`
- `tools/node115_lu_collect.py`
- `tests/test_node115_lu_collect.py`
