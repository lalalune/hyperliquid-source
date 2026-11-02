# RE-001: map node #94 WAL flush phase A 0x50e9410

Task: RE-001 (#94 function map). Bounded question: in the WAL flush
driver mapped by PR #1892, what gates does phase A run before it adds
one looked-up object to the flush collection, and what does it append
and log when every gate passes?

- Component: node #94 WAL flush phase A, window `0x50e9410..0x50e95d4`
  (452 bytes, single FDE 0xf79398, cie=0xce1518, no LSDA), plus its
  lookup call contract (0x4fec940), its overflow grow call contract
  (0x4fc75e0) and its log tail-call contract (0x522ea30). The
  callee internals are not pinned here.
- Target release and full SHA-256: node #94, `work/hl-node-94.bin`,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Claim status: observation for the argument roles, the collection
  layout, the gate order, the already-present search, the
  smallest-key rule, both append arms, the grow call, the log record
  and its rodata strings, the canary frame, and the three direct
  callers; inference for the ordering-key reading of the +0x948
  field and the name-string reading of the db +0x360 log argument;
  unresolved for the callee internals, the struct types, the
  source-level meaning of the +0x948 key and the +0x4c9 flag, and
  the call arguments of the two non-driver callers (see records.json).
- Note on evidence text: the raw disassembly excerpts are verbatim
  objdump output. Instruction mnemonics appearing in them (including
  `endbr64` at the window entry) are genuine instructions present in
  the target binary, not placeholders; the packet checker re-verifies
  sampled instructions byte-for-byte against a fresh objdump run and
  the raw binary.

## Tool versions

- objdump: GNU objdump (GNU Binutils for Ubuntu) 2.42
- Python: 3.12.3
- Invocation: `objdump -d --start-address=<start>
  --stop-address=<end> work/hl-node-94.bin` from the repository root
  with the relative binary path; `objdump --dwarf=frames` is not used
  for frames.txt (rows are verbatim from work/fde94/node-94-fde.tsv).

## Answer

`flush_phase_a(db, collection)` returns void. The collection is the
driver collection from PR #1892: count at +0x00 (the inline element
count, 0..8), an inline-array pointer at +0x48 (8 slots), and an
overflow vector at +0x50/+0x58/+0x60 (begin/end/capacity). Total
elements = inline count + (overflow end - overflow begin) / 8.
Element `i` reads inline slot `i` for `i < 8` and
`overflow_begin[i - 8]` for `i >= 8` (the bytes compute
`overflow_begin - 0x40 + i * 8`).

The gates run in this order; each failing gate returns silently, with
no append and no log:

1. Empty collection: total elements == 0 returns immediately, before
   the flag is even read.
2. Phase flag: the byte at db +0x4c9 == 0 returns immediately.
3. Lookup: call 0x4fec940 with (the object at [db +0x68] +0x40, the
   static .bss object at 0x57887a0). A null result returns
   immediately. The .bss object's runtime content is not pinned.
4. Chain guard: dereference the result's +0x8e8 field, then that
   object's +0xc18 field; a null at either step returns immediately.
   The final value is discarded — this is a validity gate, not a
   value load.
5. Already present: if any collection element pointer equals the
   lookup result, return immediately.
6. Smallest-key rule: walk the list headed at [[db +0x68] +0x40]
   +0x110 (nodes linked by +0x938, the head address itself is the
   sentinel). For each node, first compare the node pointer with
   the lookup result pointer and skip the node when they are
   identical; otherwise, if the node's +0x948 field is less than or
   equal to the lookup result's +0x948 field (unsigned; the bytes
   are `cmp target,node` followed by `cmovae` to clear the flag),
   return immediately. An empty list passes. So the append happens
   only when the lookup result's +0x948 is strictly smaller than
   every other list node's +0x948.

On passing all gates, the window appends the lookup result:

- Inline arm (inline count <= 7): store at
  inline_array_pointer[inline count], then inline count += 1.
- Overflow arm (inline count > 7): if the overflow end already
  equals the overflow capacity, call the grow helper 0x4fc75e0 with
  (the overflow vector address at collection +0x50, the overflow
  end, a stack pointer whose role is not pinned); then store at the
  old overflow end and advance the overflow end by 8.

Then it tail-calls the log callee 0x522ea30 with (level 1,
db +0x360, "[%s:1980] Force flushing stats CF with automated flush
to avoid holding old logs" at rodata 0x7d6a08,
"db/db_impl/db_impl_write.cc" at rodata 0x7e1960).

Reachability: exactly three direct callers, no tail jumps, no qword
references (full .text E8/E9 scan plus whole-file qword scan in
census.py): 0x50ec19c in the flush driver 0x50ebfb0..0x50ec9d7
(PR #1892, collection at driver frame -0x1d0), 0x50ecc3e in
0x50eca90..0x50ed403, and 0x50ed5a0 in 0x50ed4b0..0x50edda0 (the
latter two are census only). The window's own frame carries a stack
canary at rsp+0x08, checked on every return path and before the log
tail-call; canary failure calls __stack_chk_fail at 0x50e95be.

## Model and tests

- `tools/wal_flush_phase_a.py`: the phase model (gates, both append
  arms, grow contract, log record).
- `tests/test_wal_flush_phase_a.py`: gate order, both append arms,
  the 8-slot inline boundary, the strictly-smaller key edge,
  unsigned key comparison, and the packet checker itself.
