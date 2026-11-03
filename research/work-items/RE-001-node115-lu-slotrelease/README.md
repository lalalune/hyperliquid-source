# RE-001: the node #115 lu slot-release helper

## Question

Packet #223's next question: what does the FDE `0x63b0780..0x63b097f`
do with its slot before and after the slot-remove call (call site
`0x63b0847` to `0x63acb40`), and why does it immediately call
`0x63abcf0` with the same slot?

## Answer

`0x63b0780(record, node)` = (rdi, rsi) releases one node from its
size-class slot and updates every piece of pool accounting for that
class. Before the remove it computes the size-class index and
decrements the class counters; after the remove it tests whether the
slot is now empty — that test is exactly why `0x63abcf0` is called
immediately, with the same slot: an empty slot clears its presence bit
in the record's bitmap, while a non-empty slot keeps its cached key
fresh instead. The function makes exactly four calls, has a single
`ret` site (`0x63b08cf`), and returns nothing meaningful: all four
census callers ignore its return value.

## Entry and size-class index

- Entry: `endbr64`, save callee-saved registers, `rbp = record`,
  `rbx = node`.
- `r12 = [node+0x10] & ~0xfff` — the node's size word, page-aligned.
  This is the same `+0x10` size word #218's remainder helper reads.
- `call 0x63e8bf0(r12)` at `0x63b07a6`. The callee's internals are
  cited by address only (its `.bss` base at `0x6728140` and table at
  `0x6728180` are not in the file); its return value `v` is the only
  input to the index computation below.
- Huge: if `v >= 0x7000000000000000`, the huge path at `0x63b0950`
  hardcodes index 199 (`0xc7`): slot `S = P + 0x2590`, slot object
  `T = P + 0x1900`, saved index `0xc7`.
- Otherwise the `bsr` idiom (same shape as #216's allocator index and
  #218's remainder index): `edi = max(ceil_log2(v), 14)`,
  `shift = (edi == 14) ? 12 : edi - 3`,
  `index = (edi - 14) * 4 + (((v - 1) >> shift) & 3)`.
  Index range is 0..199; the huge path is the index-199 corner of the
  same scale.

## Record layout (all offsets mutually consistent)

With `P = record` and `i = index`:

- `P + 0x00 .. P + 0x20`: presence bitmap, one bit per class
  (4 words cover 200 classes).
- `P + 0x20 + i * 32`: slot object `T`, 32 bytes per class.
  `T = P + (i + 1) * 32` in the code. `[T]` is the chain head (#223);
  `[T+0x10]` / `[T+0x18]` hold the slot's cached key (see below);
  `[T+8]` is never touched here (identity unresolved, #223).
- `P + 0x1920 + i * 16`: class accounting `S`, 16 bytes per class.
  `S = P + (i + 0x192) * 16` in the code. `[S]` is a block count,
  `[S+8]` is a byte total.
- `P + 0x25a0`: recorded node (cursor, see below).
- `P + 0x25a8`: page counter.
- Check: `0x20 + 200 * 32 = 0x1920`, `0x1920 + 200 * 16 = 0x25a0`,
  and the huge path's `S = P + 0x2590 = P + 0x1920 + 199 * 16`,
  `T = P + 0x1900 = P + 0x20 + 199 * 32`. Exact.

## Before the remove: accounting decrement

- `[S] -= 1` (`0x63b0821`–`0x63b082b`).
- `[S+8] -= r12` (`0x63b082e`–`0x63b0834`) — the page-aligned size in
  bytes. There is no guard before either decrement.
- Key pair saved: `r14 = [node+0x20]`, `[rsp+8] = [node+0x8]`.
- `call 0x63acb40(T, node)` at `0x63b0847` — #223's slot-remove
  helper, `(slot, node)` per #223's arg convention. `rsi` is still
  the node; only `rdi` is reloaded with `T`.

## After the remove: the empty test and why it comes first

- `call 0x63abcf0(T)` at `0x63b084f` with `rsi` still the node.
  `0x63abcf0` is 12 bytes: `cmpq $0,(%rdi); sete %al; ret` — it
  returns 1 exactly when the slot's chain head `[T]` is NULL, i.e.
  when the remove just emptied the slot. That is the whole reason
  for the immediate call: the two post-remove updates are mutually
  exclusive, and emptiness decides between them.
- Empty (`al != 0`): clear the class bit — `word = i >> 6`,
  `mask = rol(~1, i)`, `[P + word * 8] &= mask`
  (`0x63b085c`–`0x63b086a`). A cleared bit means "no blocks left in
  this class".
- Non-empty (`al == 0`): fall to the cache-refresh block
  (`0x63b08d0`). `C = P + i * 32`, so `[C+0x30]` / `[C+0x38]` are
  `[T+0x10]` / `[T+0x18]`, the cached key. The block compares the
  cached key against the removed node's (`+0x20`, `+0x8`) key with
  the two-sided `setb` idiom on each word; if either word differs it
  skips to the cursor block. If both match — the removed node was
  the cached node — it calls `0x63abd00(T)` at `0x63b0912` and
  copies the returned node's key into the cache:
  `movq 0x20(%rax), %xmm0; movhps 0x8(%rax), %xmm0;
  movups %xmm0, [C+0x30]`. Only the caller's use of the returned
  node's key is claimed here; `0x63abd00`'s own contract (which
  node it returns, whether it mutates the chain) is unresolved.

## Cursor, list rewiring, page counter (all paths converge here)

- `cmp [P+0x25a0], node` (`0x63b086f`). If the removed node is the
  recorded node: `r14 = [node+0x40]`; if `r14 == node` (self-loop,
  singleton) then `[P+0x25a0] = 0` and the rewiring block is
  skipped; otherwise `[P+0x25a0] = r14` and the rewiring block runs.
  If the removed node is not the recorded node, the rewiring block
  runs directly.
- Rewiring block (`0x63b087c`–`0x63b08a8`), with `A = [N+0x40]`,
  `B = [N+0x48]`, `r8 = [A+0x48]`: `[B+0x40] = r8`,
  `[A+0x48] = B`, `[N+0x48] = r8`, `[B+0x40] = A`,
  `[r8+0x40] = N`. Under the consistent circular-list reading
  (`+0x40` = next, `+0x48` = prev, confirmed by the cursor
  advancing along `+0x40` and the self-loop singleton case) this
  unlinks `N` from the list and self-loops `N`'s links
  (`r8 == N` on entry in a consistent list). The list's global
  purpose — what `P+0x25a0`'s list contains — is unresolved.
- Page counter: `[P+0x25a8] -= r12 >> 12` (`0x63b08ac`–`0x63b08ba`),
  i.e. the page-aligned size converted to pages.
- Single exit: restore registers, `ret` at `0x63b08cf`.

## Census

Whole-`.text` byte scan + per-site disassembly; `.rela.dyn` for GOT
(60,723 entries). Release helper `0x63b0780`: 4 direct E8, 0 E9,
0 LEA, 0 GOT. E8: `0x63b1bc4` and `0x63b1c91` (both in #213's chain
helper FDE `0x63b1b60..0x63b1d35`, passing (record, node) with the
node from the next-node call), `0x63b26f1` (in #210's selector FDE
starting `0x63b2630`), `0x63b47ca` (in the FDE starting `0x63b4630`,
not decoded here). All four callers ignore the return value. The
non-chain callers' purposes are cited by address only, not decoded
here.

## Corrections to earlier packets

- **#223 confirmed.** The remove call site `0x63b0847` passes
  (slot, node) per #223's arg convention, and #223's census already
  listed `0x63b0847` as a remove caller; the slot object `T` here
  is the same 32-byte-entry table #223's helper operates on.
- **#213 refined.** The chain helper's `0x63b0780` calls (sites
  `0x63b1bc4`, `0x63b1c91`) are to this 512-byte release helper
  with a void return ignored by every caller — not to a
  byte-returning test. The "byte test" gloss is not adopted here.
- **#216 / #218 confirmed.** The `bsr` / `sbb` / clamp index idiom
  is the same one the allocator worker (#216) and the remainder
  helper (#218) use, extended here with the `(edi - 14) * 4`
  group scaling and the index-199 huge corner.
- No bytes claimed by packets #183–#223 are re-claimed. All exhibits
  lie strictly inside the release FDE; the remove helper, the
  empty-test, the refresh callee, the size helper, and all caller
  FDEs are cited by address only.

## Unresolved, stated not inferred

The contract of `0x63abd00` (which node it returns for a slot, and
whether it mutates the chain — it zeroes `[slot+8]` and `+0x28`
pairs on its entry paths); the contents of the size helper's `.bss`
base (`0x6728140`) and table (`0x6728180`), hence what
representative value it returns for a given page-aligned size; the
identity of the slot's second word `[T+8]`; the global purpose of
the `+0x40` / `+0x48` list and of the `P+0x25a0` recorded node;
the purposes of the four callers beyond their call sites.

## Next question

Decode `0x63abd00` end to end: what node it returns for a slot, and
whether it mutates the chain — this decides whether the cache
refresh in this packet is read-only, and what the slot's cached key
actually tracks.

## Verification

- Static verifier `tools/node115_lu_slotrelease.py`: exit 0
  (5 excerpts, 298 bytes, 81 strict mnemonics, 4 internal calls,
  census 4 E8 sites, MANIFEST 15/15).
- Unit tests `tests/test_node115_lu_slotrelease.py`: 9/9.
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
- No bytes claimed by packets #183–#223 are
  re-claimed; earlier bytes are cited by address
  only. No execution of the node binary at any
  point.

## Files (16)

- `research/work-items/RE-001-node115-lu-slotrelease/README.md`
- `research/work-items/RE-001-node115-lu-slotrelease/EVIDENCE.md`
- `research/work-items/RE-001-node115-lu-slotrelease/records.json`
- `research/work-items/RE-001-node115-lu-slotrelease/MANIFEST.sha256`
- `research/work-items/RE-001-node115-lu-slotrelease/sr_entry.hex`
- `research/work-items/RE-001-node115-lu-slotrelease/sr_entry.objdump.txt`
- `research/work-items/RE-001-node115-lu-slotrelease/sr_index.hex`
- `research/work-items/RE-001-node115-lu-slotrelease/sr_index.objdump.txt`
- `research/work-items/RE-001-node115-lu-slotrelease/sr_acct.hex`
- `research/work-items/RE-001-node115-lu-slotrelease/sr_acct.objdump.txt`
- `research/work-items/RE-001-node115-lu-slotrelease/sr_clear.hex`
- `research/work-items/RE-001-node115-lu-slotrelease/sr_clear.objdump.txt`
- `research/work-items/RE-001-node115-lu-slotrelease/sr_cache.hex`
- `research/work-items/RE-001-node115-lu-slotrelease/sr_cache.objdump.txt`
- `tools/node115_lu_slotrelease.py`
- `tests/test_node115_lu_slotrelease.py`
