# RE-001: pin node #115 HashLinkListRep slot 0x90: the index rebuild, the per-bucket chain-length histogram and its log report

Task: RE-001 (#115 function map). Bounded question: how does
`HashLinkListRep`'s slot-0x90 method rebuild its entry index, measure
the per-bucket chain-length distribution, and report it?

- Component: node #115 PlainTable hash-linked-list representation,
  extracted from the digest-verified work binary (SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  provenance/artifacts.json path `artifacts/node/115/hl-node`):
  windows `0x605feb0..0x6060199` (host, slot 0x90),
  `0x605dd90..0x605dfcd` (`rocksdb::Arena` ctor),
  `0x605f290..0x605f33a` (0x38-byte index builder),
  `0x605f340..0x605f6d5` (index insert with rehash),
  `0x5fcef60..0x5fcf043` (level-gated log dispatch),
  `0x605cfa0..0x605cfd6` (block-size normalizer),
  `0x605e830..0x605e859` (conditional atomic counter add),
  `0x61c4080..0x61c4117` (per-thread hash seed),
  plus the re-shipped HistogramImpl callees `0x606b080..0x606b0a2`
  (bucket-count init), `0x606b0c0..0x606b10a` (locked init),
  `0x606b1c0..0x606b1cd` (record thunk), `0x606b130..0x606b1b3`
  (record) and `0x606bc90..0x606bcd3` (ToString entry).
- Claim status: observation for the window bounds, the field writes,
  the vtable slots, the seed/hash arithmetic, the chain walk, the
  record/render/log steps and the iterator construction; inference
  for the names "HashLinkListRep", "Arena", "FullListIterator"
  (all read verbatim from their typeinfo name strings), "index",
  "chain" and "bucket" (they describe the observed roles, not proven
  source names); unresolved for the items listed in records.json.
- Note on evidence text: the raw disassembly excerpts are verbatim
  objdump output. Instruction mnemonics appearing in them (including
  `endbr64` at the window entries and at each landing pad) are
  genuine instructions present in the target binary, not
  placeholders; the packet checker re-verifies sampled instructions
  byte-for-byte against a fresh objdump run and the raw binary.
- Relationship to earlier work: no open PR covers the host, the
  Arena ctor in this use, the index builder/insert, the log gate,
  the normalizer, the counter add or the thread seed (checked this
  cycle: open-PR snapshot of 91 open WalkCrypto PRs, no title hit;
  `gh search issues --include-prs` in lalalune/hyperliquid-source
  returns 0 hits for 605feb0, 605dd90, 605f290, 605f340 and 5fcef60).
  The five HistogramImpl excerpts are pinned in open PR #3371
  (RE-001-histogram-stats-family-115) and are re-shipped here
  byte-identical as the host's histogram callees; the excerpts were
  regenerated from the same binary and ranges. The record/render
  rules and the 109 bucket boundaries follow #3371. The `map_find_name`
  hash seed `0xc70f6907` also appears in #3563. The host's sibling
  slot-0x08 method `0x605f700` (which also builds an index via
  `0x605f290`/`0x605f340` and logs via `0x5fcef60`) and the other two
  record-thunk callers `0x6198900`/`0x6198d40` are separate work
  items, not pinned here.

## The host 0x605feb0, stated literally

`HashLinkListRep` vtable slot 0x90 (vtable base `0x64d2168`,
typeinfo `*N7rocksdb12_GLOBAL__N_115HashLinkListRepE` — the leading
`*` is the byte present in the binary's typeinfo name string, not a
transcription artifact). Arguments: rdi = this, rsi = an allocator
object or null. It returns a `FullListIterator` (vtable `0x64d2090`).

1. Allocate `0x8f0` bytes and build a `rocksdb::Arena` via the ctor
   `0x605dd90(out, size, 0, 0)`, where `size` is the result of the
   virtual call `slot 0x20` on `*(this+0x08)` (no arguments).
2. Allocate a 0x38-byte index via the builder `0x605f290(idx,
   *(this+0x30), count=0xc, arena, divisor=4)`.
3. Build a stack `HistogramImpl` at rsp+0x50: vtable `0x64d2b80`,
   bucket-count init `0x606b080` on the inner pointer (rsp+0x58),
   locked init `0x606b0c0` on the outer pointer.
4. For each bucket `i` in `0..this+0x10 - 1`: take the bucket head
   `this+0x18[i]`; if null, the bucket contributes a count of 0.
   Otherwise walk the bucket's chains, calling the insert
   `0x605f340(idx, &chain_head)` once per entry and counting the
   entries in r14d. Two chain shapes are walked: a plain list
   linked via `*(node)`, and a list reached via `node+0x28` then
   `+0x08`. The `*(this+0x08)` object is never dereferenced here;
   only its slot-0x20 result (step 1) is used.
5. If the flag byte at `this+0x44` is non-zero, record the
   per-bucket count into the stack histogram via the record thunk
   `0x606b1c0(hist, count)` (vtable slot 0x20, tail-jumps to
   `0x606b130`).
6. If the flag is non-zero and `this+0x38` (the logger) is
   non-null, render the histogram via the ToString entry
   `0x606bc90(out_string, hist)` and log it via the log gate
   `0x5fcef60(logger, "hashLinkedList Entry distribution among
   buckets: %s", rendered)`.
7. Build a 0x48-byte `FullListIterator` (vtable `0x64d2090`) over
   (index, arena): the storage comes from the saved 2nd argument's
   vtable slot 0x18 `(alloc, 0x48, 0, 0)` when that argument is
   non-null, else from operator new; the iterator's `+0x08` and
   `+0x18` hold the index, `+0x20` holds the Arena, `+0x28` holds
   its own `+0x38`. Return the iterator pointer.

The host has no direct call or tail-jump site in the binary: it is
reached only through the vtable slot (RELATIVE at `0x64d21f8`).

## The Arena ctor 0x605dd90, stated literally

The general `rocksdb::Arena` ctor (vtable `0x64d1fb8`, typeinfo
`N7rocksdb5ArenaE`); 19 direct callers across the binary, pinned
here because the host builds an Arena. Arguments: rdi = out (0x8f0
bytes), rsi = block-size hint, rdx = arg3, rcx = arg4.

1. Install the vtable at `*(out)`; call the size normalizer
   `0x605cfa0(size_hint)` and store the result at `out+0x810`.
2. `out+0x818` = a 64-byte block (8 slots); `out+0x820` = 8.
   `out+0x828..0x868` = two identical 32-byte table descriptors
   `{512-byte block, 512-byte block, 512-byte block + 0x200,
   64-byte block + 24}`.
3. The same construction repeats at `out+0x860..0x8b8` (the second
   table, with its own 64-byte and 512-byte blocks).
4. Tail struct at `out+0x8b8..0x8f0` (0x38 bytes): `+0x8b8` = 0,
   `+0x8c0` = `&out+0x810`, `+0x8c8` = `out+0x10`, `+0x8d0` =
   `0x800`, `+0x8d8` = arg4 when arg4 == 0 or arg4 >= the normalized
   size, else `ceil(size / arg4) * arg4`, `+0x8e0` = `0x800`,
   `+0x8e8` = arg3.
5. If arg3 != 0: `counter_add 0x605e830(arg3, 0x800)`.

The host passes `(size, 0, 0)`, so its tail fields are `0x800 /
0 / 0x800 / 0` and no counter-add runs.

## The index builder 0x605f290, stated literally

Builds the 0x38-byte index. Arguments: rdi = out, rsi = key object,
rdx = allocator, ecx = count (u16), r8d = divisor (u16).

- `+0x00` = count, `+0x02` = divisor, `+0x04` = `0x80000000 /
  divisor` (the rehash step), `+0x08` = key object, `+0x10` =
  allocator.
- `+0x18` = array A, allocated through the allocator's vtable slot
  0x18 with `(count+1)*8` bytes, all `count+1` slots zeroed.
- `+0x28` = array B, allocated through the same slot with
  `count*8` bytes; every slot is set to array A.
- `+0x20` = 1, `+0x30` = 1 (initial capacity/size markers).

## The index insert 0x605f340, stated literally

Inserts one key record into the index. Arguments: rdi = index,
rsi = pointer to the key record.

1. Comparator dispatch: slot 0x08 of `*(index+0x08)` is called on
   (key, candidate) and returns negative / zero / positive.
2. Scan array A from the end (`index+0x20 - 1` down to 0),
   comparing each occupied slot's key; a negative compare restarts
   the scan from the matched slot.
3. When the scan reaches array A's head without a match, rehash:
   advance the per-thread seed via `0x61c4080` — multiply by
   `0x41a7` mod `0x7fffffff` until the value reaches the step at
   `+0x04`, capped by the count — and store the advanced seed back
   into the thread slot.
4. Grow array A to the new size (memmove of the entries) when
   `+0x20` is smaller; set `+0x20` and `+0x30` to the new size.
5. Allocate a node through the allocator's slot 0x18, store the
   key, and splice it into the chain (linked-list insert ordered by
   the comparator).

The hash constants are the multiplier `0x41a7`, the modulus
`0x7fffffff` (Mersenne reduction: `(v & 0x7fffffff) + (v >> 31)`,
with one `0x7fffffff` subtraction when the 32-bit sum overflows
into bit 31 — the `cmovs` after the add, whose flags come from the
add because `lea` does not touch flags), and the step from
`+0x04`.

## The log gate 0x5fcef60, stated literally

Arguments: rdi = logger, rsi = format string, plus varargs.

1. Spill the varargs (rdx/rcx/r8/r9 and xmm0..xmm7 when al != 0)
   into a stack args array.
2. Call the logger's vtable slot 0x40; if the returned level is
   greater than 1, return without logging.
3. Otherwise call the logger's vtable slot 0x28 with (level = 1,
   format, args pointer).

## The size normalizer 0x605cfa0, stated literally

`normalize_block_size(n)`: `n <= 0x1000` returns `0x1000`;
`n >= 0x80000000` returns `0x1000`; otherwise `n` rounded up to a
multiple of 16.

## The counter add 0x605e830, stated literally

Arguments: rdi = object, rsi = delta. Load the guard pointer
`*(obj)` and its vtable slot 0x00; if that slot is null AND
`*(slot_obj+0x20) == 0`, return without touching anything.
Otherwise `lock add delta, *(obj+0x08)` and tail-jump to
`0x606a0c0` with rdi = `*(obj)`. The tail callee is not excerpted
(recorded as a boundary).

## The thread seed 0x61c4080, stated literally

Returns a pointer to the cached per-thread seed (u32). The thread
pointer comes from `%fs:0x0`; the cached pointer lives at
thread-0x10 and the cached value at thread-0x20. If the cached
pointer is non-null, return it. Otherwise compute
`_Hash_bytes(&pthread_self, 8, 0xc70f6907) & 0x7fffffff`, or 1 when
that is 0; store the value at thread-0x20 and the pointer
(thread-0x20) at thread-0x10; return the pointer. The seed
constant `0xc70f6907` is the same one `map_find_name 0x5d66e30`
uses (#3563).

## The HistogramImpl callees, stated briefly

Re-shipped byte-identical from #3371; see that packet for the full
record. Bucket-count init `0x606b080` writes the bucket count;
locked init `0x606b0c0` is vtable slot 0x10; the record thunk
`0x606b1c0` is vtable slot 0x20 and tail-jumps to record
`0x606b130` (bucket = lower_bound over the 109 generated
boundaries; buckets[bucket]++, min/max/count/sum/sumSq updated);
the ToString entry `0x606bc90` is vtable slot 0x30 and calls the
renderer `0x606b6f0`, whose lines are: `Count: %lu Average: %.4f
StdDev: %.2f`, `Min: %lu  Median: %.4f  Max: %lu`, `Percentiles:
P50/P75/P99/P99.9/P99.99`, a 54-dash separator, then one row per
non-empty bucket (`[ (lower, upper] count pct cum-pct` plus `#`
repeated `round(pct / 5)` times). The other two direct callers of
the record thunk are `0x6198ae7` (FDE `0x6198900..0x6198ce2`) and
`0x6198e2a` (FDE `0x6198d40..0x6198f4d`); the second also renders
ToString and logs `[%s:101] Number of Keys per prefix Histogram:
%s` — both are separate work items.

## Vtables pinned

- `HashLinkListRep` 0x64d2168, 23 slots 0x00..0xb0 (slot 0x90 =
  the host 0x605feb0; slot 0x08 = the sibling 0x605f700).
- `Arena` 0x64d1fb8, 5 slots 0x00..0x20.
- `FullListIterator` 0x64d2090, 11 slots 0x00..0x50.
- `HistogramImpl` 0x64d2b80, slots 0x10/0x20/0x30 pinned here
  (the full 16-slot table is in #3371).

## Verification

`python3 research/work-items/RE-001-chain-histogram-snapshot-115/verify.py`
prints ALL CHECKS PASSED: binary and provenance digests, manifest,
excerpt regeneration, fixed samples plus 3 seeded random gate spots
byte-for-byte against a fresh objdump run and the raw binary,
frames, census reproduction (76 verified call sites), relocations,
vtables, literals, and the model tests
(`tests/test_chain_histogram_snapshot_115.py`, 282 checks).
