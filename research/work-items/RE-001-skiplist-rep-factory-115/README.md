# RE-001: pin node #115 SkipListFactory slot-19 factory 0x6063640 — the two SkipListRep products, the owner dispatch, the ConcurrentArena, and the transient holder teardown

Task: RE-001. Bounded question: how does node #115 build the two
SkipListRep products at owner+0xa50/+0xa58 — which factory routine
builds them, how does the owner dispatch between the virtual and
the direct call, what does the ConcurrentArena at owner+0xa0
contribute, and what happens to the transient factory holder
afterwards?

Target: node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
(`work/hl-node-115.bin`, verified against
`provenance/artifacts.json`). All addresses below are node #115
virtual addresses; all excerpts are whole-function verbatim
objdump output. The mnemonics in the excerpts (`endbr64`
included) are genuine instructions present in the target binary,
not placeholders.

This packet picks up the ground PR #3272 explicitly left open:
its fifth holder-ctor call site (`0x5f10517`) builds a transient
holder for this consumer (`0x6063640`), which #3272 recorded in
its census but did not model. The holder ctor excerpt itself is
re-shipped byte-identical from #3272.

## What this pins (complete behaviour, not a fragment)

1. **The owner dispatch.** The owner `0x5f103f0..0x5f10cf8`
   (0x908 bytes; only the `0x5f104cd..0x5f105a0` window and the
   `0x5f10c40..0x5f10c53` non-canonical branch are pinned here)
   reads the factory at `*(r13+0x2a8)` and the factory vtable's
   slot 20, and compares it with the GOT entry `0x64ed780`,
   whose RELATIVE addend is `0x5f04d90` — the canonical
   forwarder (`endbr64; mov (%rdi),%rax; jmp *0x98(%rax)`), which
   forwards every argument to slot 19. When the slot is
   canonical, the owner calls slot 19 (`0x6063640`) with
   `(factory, owner, &owner+0xa0, *(r14+0x40), *(r13+0x220))`
   and stores the SkipListRep\* at owner+0xa50. When it differs,
   the owner calls slot 20 itself (`call *%r10`) with one extra
   argument (`r9` = the owner's stack argument) and jumps back
   to the same +0xa50 store.
2. **The factory.** `0x6063640` (272 bytes, `0x6063640..0x6063752`,
   SkipListFactory vtable slot 19) allocates a 0x58-byte
   `rocksdb::(anonymous namespace)::SkipListRep` (vtable
   `0x64d26e8`, typeinfo name as stored
   `*N7rocksdb12_GLOBAL__N_111SkipListRepE` — the stored name
   carries a leading `*` byte) and fills it: +0x00 vtable,
   +0x08/+0x18 = the arena address, +0x10 =
   `0x200000000004000c` (u16 count 12, u16 4, u32 `0x20000000`),
   +0x20 = owner, +0x28 = first allocation + 0x58, +0x30 = 1,
   +0x38 = second allocation, +0x40 = owner, +0x48 = the rcx
   argument, +0x50 = the factory record's `a` (factory+0x20).
   Both allocations go through the arena's slot 3
   (`AllocateAligned`, merged PR #2160): the first is 0x60
   bytes, gets 12 written at +0x58, then all 12 qwords are
   zeroed (the 12 write is overwritten by the loop; the final
   state is all zero); the second is 0xe8 bytes —
   `0x18 + 2 * (8 + 8 * count)` with count = 12 — with u32 0 at
   +0x00, self+0x18 at +0x08 and self+0x80 at +0x10 (two
   (count+1)\*8-byte regions).
3. **The second product and the transient holder.** The owner
   then builds a transient 0x28-byte SkipListFactory holder on
   the stack with the ctor `0x6064440` (re-shipped from #3272)
   with `a = 0`, so its single record is
   `{"SkipListFactoryOptions", 0, 0x6505c40}`, and calls the
   same factory `0x6063640` directly with
   `(holder, owner, &owner+0xa0, 0)`; the second SkipListRep\*
   lands at owner+0xa58. The two products differ only in +0x48
   (the virtual call's rcx vs 0) and +0x50 (the real factory's
   `a` vs 0). The holder is then destroyed in place: its vptr
   is reset to the `rocksdb::Configurable` vtable `0x64d3430`
   (typeinfo `N7rocksdb12ConfigurableE`), each heap key of the
   record vector is freed with `len+1` bytes (the 22-char key is
   heap-allocated), and the vector buffer is freed when non-null.
4. **The arena.** The arena at owner+0xa0 is a
   `rocksdb::ConcurrentArena` (vtable `0x64cc5d8`, 0x9b0 bytes —
   the size comes from the sized deleting dtor `0x5f10d00`,
   merged PR #2133 — so it spans owner+0xa0..owner+0xa50,
   immediately before the two product pointers). Its init
   `0x605e010` (called exactly once, from the owner at
   `0x5f104c8`) sets +0x40 = `rsi/8`, capped at `0x20000` when
   `rsi >= 0x100000`; +0x50 = shard bits (3 when
   `hardware_concurrency <= 8`, else the smallest ecx >= 4 with
   `2**ecx >= hw`); allocates a 0x40-byte-per-shard array at
   +0x48 with each shard's +0x28 byte and +0x30/+0x38 qwords
   zeroed; then calls the +0x60 sub-init and copies the
   +0x918/+0x930/+0x940 stat triple into the +0x958/+0x960/+0x968
   shadow, clearing the +0x950 lock byte. The +0x60 sub-init
   `0x605dd90` installs the embedded `rocksdb::Arena` vtable
   `0x64d1fb8` and builds two block pairs: a 0x40-byte block
   whose +24 slot holds a 0x200-byte block, and a second
   0x40/0x200 pair; it records the aligned block size at
   arena+0x870, +0x930 = +0x940 = `0x800`, +0x938 = the rounded
   size, and keeps &owner+0x80 at +0x948. The +0x80 header
   (init `0x605e810`) is `{ptr, 0, u16 0}`. The huge-page align
   helper `0x605cfa0` returns `0x1000` when its argument is
   `<= 0x1000` or `>= 0x1000 + 0x7ffff000`, else rounds it up to
   a 16-byte boundary; owner+0x78 and arena+0x870 both hold
   `huge_align(*(owner+0x18))`. The arena's slot 4
   `0x5f04da0` returns `*(arena+0x870)`.
5. **The forwarders.** `0x5f04d90` (canonical slot 20) forwards
   to slot 19; `0x5f04d80` (SkipListRep slot 19) forwards to
   slot 18 (`0x6063070`); `0x5f04d50`/`0x5f04d60` (SkipListRep
   slots 10/11) are `endbr64; ret` no-ops. These tiny functions
   are shared across several vtables and GOT slots (e.g.
   `0x5f04d90` is also installed at GOT `0x64ed780` and at three
   other vtable slots); the census records every installation.

## Census (callers.tsv, 100,123 rows)

The factory `0x6063640` has exactly one direct call site:
`0x5f10530` (the direct call in the owner window); its virtual
call reaches it through `call *0x98(%rax)` at `0x5f104fc`,
which the census cannot attribute to a single address. The
holder ctor `0x6064440` has five call sites
(`0x5d94ce8`, `0x5f10517`, `0x60b3dd2`, `0x6193685`,
`0x619371a`). The arena init `0x605e010` has one (`0x5f104c8`);
the sub-init `0x605dd90` has 19 (including `0x605e0f4` from the
arena init); the small init `0x605e810` has one (`0x5f1048c`);
the huge-align helper `0x605cfa0` has two (`0x5f10471`,
`0x605ddb8`). The owner `0x5f103f0` has exactly two direct
callers: `0x5d8ca47` and `0x5ed08ab`.

## Vtable slots pinned from relocations.txt

SkipListRep vtable `0x64d26e8` (23 slots): 0 `0x6063150`,
1 `0x6065f80`, 2 `0x6065f60`, 3 `0x6065ec0`, 4 `0x6065fa0`,
5 `0x6066680`, 6 `0x6066710`, 7 `0x6066670`, 8 `0x6066660`,
9 `0x6064930`, 10 `0x5f04d50` (no-op), 11 `0x5f04d60`
(no-op), 12 `0x6065040`, 13 `0x60646d0`, 14 `0x6066f20`,
15 `0x6062fb0`, 16 `0x6062fc0`, 17 `0x6063010`,
18 `0x6063070`, 19 `0x5f04d80` (forwards to slot 18),
20 `0x5e572d0`, 21 `0x5d483f0`, 22 `0x5f05db0`.
SkipListFactory vtable `0x64d27b0` (23 slots): 0 `0x60633a0`,
1 `0x6063430`, 2 `0x609d760`, 3 `0x609dc40`, 4 `0x5d32560`,
5 `0x6095e70`, 6 `0x6096790`, 7 `0x5d2e090`, 8 `0x60956f0`,
9 `0x609d0e0`, 10 `0x60986b0`, 11 `0x6095710`, 12 `0x609de80`,
13 `0x609d980`, 14 `0x6062f70`, 15 `0x6063970`, 16 `0x5d2e770`,
17 `0x5d2ca00`, 18 `0x6062f80`, 19 `0x6063640` (this factory),
20 `0x5f04d90` (forwards to slot 19), 21 `0x6062f90`,
22 `0x6062fa0`. Slots 2..13, 16, 17 and 20 are shared with
the HashLinkListRepFactory vtable pinned in #3272.
ConcurrentArena vtable `0x64cc5d8` (5 slots): 0 `0x5f10180`,
1 `0x5f10d00`, 2 `0x5f11c40` (merged #2170), 3 `0x5f117a0`
(merged #2160), 4 `0x5f04da0`. Embedded Arena vtable
`0x64d1fb8` (5 slots): 0 `0x605cc30` (merged #2133),
1 `0x605cf80`, 2 `0x605d930`, 3 `0x605d7b0` (merged #2150),
4 `0x605cc20`. Configurable vtable `0x64d3430` (14 slots):
0 `0x60957a0`, 1 `0x6095830`, 2 `0x6099030`, 3 `0x60996a0`,
4 `0x5d32560`, 5 `0x6095e70`, 6 `0x6096790`, 7 `0x60958c0`,
8 `0x60956f0`, 9 `0x609d0e0`, 10 `0x60986b0`, 11 `0x6095710`,
12 `0x60985e0`, 13 `0x6095a60`; slots 4..6 and 8..11 are shared
with the SkipListFactory vtable. Un-named slots are recorded
by address only; their methods are not named here.

## What is NOT claimed

- The owner's other phases (+0xa60.. region init, the 0xc40
  0x38-byte element array, the shared_ptr installs) and the
  roles of its two callers (`0x5d8ca00..0x5d8ca6a`,
  `0x5ed01f0..0x5ed2238`): out of scope, listed as follow-up
  ground.
- The +0x80 header's role and the `0x605e830` register helper
  (conditional +0x800 bump + tail call to `0x606a0c0`):
  observed only, not modelled.
- The shard-refill routine `0x605e170` (2 callers, both inside
  the merged allocate routines) and the embedded Arena slots
  1/2/4 (`0x605cf80`, `0x605d930`, `0x605cc20`): referenced
  only.
- The arena slot-2/slot-3 internals, the slow path
  `0x605d7b0`, the destructor pair and the member dtor
  `0x605cc30`, and the owner's `0x5f0b420` callee: merged ground
  (#2170, #2160, #2150, #2133, #2124) — cited, not remodelled.
- The un-named vtable slots: recorded by address only.

## Verification

`python3 research/work-items/RE-001-skiplist-rep-factory-115/verify.py`
prints ALL CHECKS PASSED: digest, manifest, the re-shipped
holder excerpt, excerpt regeneration byte-for-byte from fresh
objdump runs, every excerpt instruction byte-for-byte against
the raw binary, spot instructions (including three picked at
random: `0x60636d1`, `0x605e0f4`, `0x5f104e9`), FDE ranges, the
relocation set (89 records), the literals, census consistency,
semantic records re-derived from the excerpts (factory product
fields, arena init/sub-init fields, the owner dispatch gate,
the holder teardown, vtable slot tables, typeinfo names via
c++filt), and the model tests.
`python3 tests/test_skiplist_rep_factory_115.py` runs the model
checks (pytest is not installed on this VM, so the test file
runs directly).
