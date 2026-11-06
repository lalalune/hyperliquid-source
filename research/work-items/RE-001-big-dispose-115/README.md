# RE-001: pin node #115 big-control _M_dispose 0x5f061b0 with its cache teardown

Task: RE-001. Target: node #115 binary `work/hl-node-115.bin`,
SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
(the digest in `provenance/artifacts.json`).

## Bounded question

What does the big `FragmentedRangeTombstoneListCache` control's
`_M_dispose` (0x5f061b0, vtable slot 2 of the 0x48-byte
`_Sp_counted_ptr_inplace` control built by the owner 0x5f103f0 in
#3304) do to tear down the cache state at `*(control+0x38)`:
which sub-objects it frees, in what order, how the embedded
sorted-unique clear at state+0x98 is run, and what its sort, tree
and Cleanable callees do? This packet pins, end to end:

- the entry: `state = *(control+0x38)` (the cache object at
  control+0x10, plus 0x28); a null state returns at once and
  frees nothing;
- the embedded clear object at state+0x98 (head fn +0x98, args
  +0xa0/+0xa8, chain head +0xb0, flag byte +0xb8, pair array
  +0xc0/+0xc8/+0xd0): exactly the layout the merged
  RE-001-sorted-unique-clear-50470-115 packet pins for the
  standalone routine 0x5d50470, inlined here with its own sort
  instantiation. Flag clear frees the pair buffer (when
  non-null) and drains the Cleanable; flag set clears the flag,
  sorts the 0x10-byte `{arg, disposer}` pairs, uniques them,
  disposes each kept pair once in sorted order, resets the array
  end to begin, runs the virtual phase (head call, then the
  chain walk), zeroes head and chain, frees the buffer, and the
  later 0x61bd0e0 call finds an empty head and returns at once.
  A null head abandons the chain (never called, never freed)
  under the zeroed pointer;
- the sort phase: `__introsort_loop` 0x5f053d0 (depth limit
  2*floor(log2(count)), or the literal -2 when the byte count is
  below 16; median of (first+1, middle, last-1) moved to first;
  Hoare partition; right part recursed on, left part looped on;
  depth 0 falls back to make-heap + sort-heap via
  `__adjust_heap` 0x5f04f80), then the final insertion sort
  (`__insertion_sort` 0x5f05120 over the whole range when it is
  at most 0x100 bytes, else over the first 0x100 bytes plus an
  inlined unguarded insertion tail for the rest);
- the Cleanable drain 0x61bd0e0 (head fn, then the +0x18 chain
  of 0x20-byte nodes, each freed) and its init 0x61bd0c0
  (zeroes +0x00 and +0x18). The drain never frees the head
  storage itself;
- the +0x80 `std::list<std::string>`: heap string buffers freed
  with `_ZdlPvm(ptr, *(node+0x20)+1)`, SSO strings free no
  buffer, each 0x30-byte node freed;
- the +0x60 singly-linked list of 0x28-byte nodes, each node's
  +0x18 subtree destroyed by the tree destroy 0x5f059b0
  (left-child/right-sibling destroy: child subtree, then the
  node, then the next sibling), each node freed with size 0x28;
- the three vectors (+0x00, +0x18, +0x30 triples) freed with
  `_ZdlPvm(begin, cap-begin)`;
- the state itself freed with `_ZdlPvm(state, 0xe8)` via a tail
  jump.

## Evidence

Every claim is bound to the binary above. Raw disassembly excerpts,
exactly as objdump emitted them (whole functions), live in this
directory: `big_dispose.txt` (whole dispose, 0x5f061b0..0x5f06548),
`introsort.txt`, `insertion_sort.txt`, `adjust_heap.txt`,
`tree_destroy.txt`, `cleanable_drain.txt`, `cleanable_init.txt`,
`frames.txt` (the 7 pinned FDEs, the cited routine FDEs, the four
routines sharing the sort/tree helpers, and the nine caller FDEs
of the merged 0x5d50470 routine). The objdump command is recorded
in `export_excerpts.py`, which is committed in this packet and
produced the excerpts. Instruction-level detail lives only in
those excerpt files; `records.json` carries semantic records only
(census, literals, field maps, gate truth tables, vtable/typeinfo
records).

Mnemonics such as `endbr64` in the excerpts are genuine instructions
present in the target binary, not placeholders.

`census.py` (committed here) produced `callers.tsv` (14995 rows) and
`relocations.txt` (17 records) from the real binary. Census summary:
dispose calls = 0 (reached only through vtable slot 2, RELATIVE
record at 0x64cc728); introsort calls = 6; insertion-sort calls =
10; adjust-heap calls = 2 (both from the introsort fallback); tree
destroy calls = 6; Cleanable drain calls = 223 + 32 tail jumps
(151 distinct caller FDEs); Cleanable init calls = 103;
sorted-unique clear calls = 9 (same set as the merged packet);
destroy dispatch calls = 654 + 36 jumps; release helper calls =
1273 + 25 jumps; operator delete calls = 11706 + 898 jumps.

## What is cited, not re-shipped

- The merged RE-001-sorted-unique-clear-50470-115 packet pins the
  standalone routine 0x5d50470 with exactly this clear behaviour
  (its sort callees 0x5d4a3f0/0x5d497e0 are a different
  instantiation from the dispose's 0x5f053d0/0x5f05120, whose
  bodies ARE pinned here); its records for the dead branch, the
  abandoned duplicates and the null-head chain abandonment are
  reused.
- The small control's `_M_dispose` 0x5f0a290 (#3304), the release
  helper 0x5d350c0 and destroy dispatch 0x5d35070 (#3263/#3304)
  and the release-loop helper 0x5f0a1dc are cited, not re-shipped.
- The sort/tree helpers are shared with four routines
  (0x5f0a3d0..0x5f0a909, 0x5f0a9c0..0x5f0b04c,
  0x5f0b080..0x5f0b418, 0x5f10d40..0x5f11798) whose own
  behaviours are follow-up ground, not claimed here.

## Correction to #3304

#3304's records named the neighbour typeinfo at 0x64cc580
"rocksdb::MemTableIterator" with name_address 0x96e660. The name
pointer is the RELATIVE record at 0x64cc588 -> 0x970970, whose
string is `N7rocksdb16MemTableIteratorE`; the 0x96e660 string
(`N7rocksdb20InternalIteratorBaseINS_5SliceEEE`) is the name of
its BASE typeinfo 0x64ca638 (RELATIVE record at 0x64ca640 ->
0x96e660). This packet records the neighbour correctly; #3304
itself is not edited.

## Verification

```
python3 research/work-items/RE-001-big-dispose-115/export_excerpts.py
python3 research/work-items/RE-001-big-dispose-115/census.py
python3 research/work-items/RE-001-big-dispose-115/verify.py
python3 tests/test_big_dispose_115.py
```

verify.py checks: the binary digest, MANIFEST.sha256, excerpt
regeneration byte-for-byte from fresh objdump runs, all excerpt
lines byte-for-byte vs the raw binary, 24 spot instructions
including 3 random ones (0x5f06234, 0x5f055b9, 0x5f06426), FDE
ranges, the 17-record relocation set, the control-counts literal,
census reproduction, semantic records re-derived from the excerpts
including the sort depth limit, the unique/dispose rules, the
vtable slot tables and the typeinfo names via c++filt, and the
model tests (152 checks, run directly; pytest is not installed on
this VM).

## Unknowns

- Bodies of the merged 0x5d50470 routine's sort callees
  0x5d4a3f0/0x5d497e0; only their call sites are pinned here.
- Identities of the head, chain-node and element-disposer callees
  and the element type names; only the call protocol is pinned.
- The purpose behind disposing each distinct pair exactly once in
  sorted order; the disposal order and the once-each rule are
  observed, the reason is not claimed.
- Behaviour when the pair-array byte count is not a multiple of
  16; the depth literal -2 for a sub-16-byte count is pinned,
  nothing further is claimed.
- Roles of state fields +0x48/+0x50/+0x58, +0x68/+0x70/+0x78,
  +0x90 and +0xd8/+0xe0, and the element types of the three
  vectors at +0x00/+0x18/+0x30; the dispose never reads them.
- Who writes *(control+0x38) (the state pointer) and when the
  cache object at control+0x10 gains its state; the dispose only
  reads it.
- What populates the +0x60 node list and the three vectors; only
  their teardown is pinned here.
