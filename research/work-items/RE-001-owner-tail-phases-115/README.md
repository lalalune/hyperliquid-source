# RE-001: pin node #115 owner 0x5f103f0 tail phases

Task: RE-001. Target: node #115 binary `work/hl-node-115.bin`,
SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
(the digest in `provenance/artifacts.json`).

## Bounded question

What do the tail phases of the owner function 0x5f103f0 do after the
SkipListFactory products are installed (the ground of #3286)? This
packet pins, end to end:

- the prologue helper 0x5f07230, which copies the option fields into
  owner+0x18 and establishes the element-array gate (+0x31 byte) and
  count (+0x38 qword);
- phase A (0x5f105a0..0x5f10766): the +0xa60 region init — zeroing,
  five self-pointers, +0xa60 = 1, +0xa80 = *(arg4), +0xc20 = +0xc28 =
  arg9;
- phase B (0x5f1076c..0x5f10838): the 0xc40 rwlock element array — the
  +0x31 gate, the 56-byte elements built by 0x60d5880, the
  `__throw_length_error` overflow arm at count > 0x249249249249249;
- phase C (0x5f10838..0x5f1091d): the +0xc48 tail init — the constants,
  the +0xc68 once-flag, the calls to 0x5f0b420 (builds the +0xd10
  table) and 0x5f07490 (runs the once predicate);
- the once predicate 0x5f07300 and its latch helper 0x5f07490, which
  consume the tail fields (+0x78, +0xa80, +0xa00, +0xe8, +0xf0,
  +0x9f8, +0xcd0);
- the small-install gate and 0x61c26f0 (the +0xc60 descriptor), the
  main install loop that installs `{&big+0x10, small}` shared_ptr
  pairs into the +0xd10 table, and the epilogue release;
- both callers of the owner (0x5d8ca00 and 0x5ed01f0).

This packet resolves one open unknown from the merged
RE-001-shared-table-resize-115 packet: the table built by 0x5f0b420
belongs to `rdi = &owner+0xd10`.

## Evidence

Every claim is bound to the binary above. Raw disassembly excerpts,
exactly as objdump emitted them (whole functions), live in this
directory: `owner.txt` (whole owner function, 0x5f103f0..0x5f10cf8),
`prologue_helper.txt`, `elem_ctor.txt`, `once_helper.txt`,
`once_pred.txt`, `small_install.txt`, `small_dispose.txt`,
`caller_small.txt`, `caller_big_window.txt`, `slot15.txt`,
`frames.txt` (the 10 FDEs). The objdump command is recorded in
`export_excerpts.py`, which is committed in this packet and produced
the excerpts. Instruction-level detail lives only in those excerpt
files; `records.json` carries semantic records only (census, literals,
field maps, gate truth tables, vtable/typeinfo records).

Mnemonics such as `endbr64` in the excerpts are genuine instructions
present in the target binary, not placeholders.

`census.py` (committed here) produced `callers.tsv` (91938 rows) and
`relocations.txt` (43 records) from the real binary. Census summary:
owner calls = 2 (0x5d8ca47, 0x5ed08ab); element ctor calls = 3
(0x5f107db, 0x6002925, 0x6067a9f); once helper calls = 7; once
predicate calls = 2 (0x5ed1bbd, 0x5f074b7); prologue helper calls = 1
(0x5f10461); small install calls = 1 (0x5f10c10); table init calls = 1
(0x5f10918); factory calls = 1 (0x5f10530), holder calls = 5; release
helper 0x5d350c0 calls = 1273, jumps = 25; destroy dispatch 0x5d35070
calls = 654, jumps = 36; strerror builder calls = 24. The control
vtable slots (big 0x64cc718, small 0x64cc750) and the SkipListRep
vtable slots are all RELATIVE relocations; the full list is in
`relocations.txt` and `records.json`.

## Model and tests

- `tools/owner_tail_phases_115.py` models the prologue helper, the
  region init, the element array (with the LengthError overflow arm),
  the tail init, the small-install gate and descriptor math, the
  install loop with reference-count release paths, the once predicate
  (all three arms) and its latch, and the caller argument bindings.
- `tests/test_owner_tail_phases_115.py`: 513 checks, run with
  `python3 tests/test_owner_tail_phases_115.py` (no pytest on this VM).
- `verify.py` in this packet re-runs the model tests, re-derives the
  census and the key records from the binary, and byte-checks spot
  instructions against a fresh objdump run. Run it with
  `python3 research/work-items/RE-001-owner-tail-phases-115/verify.py`
  from the repository root.

## What is NOT claimed

- +0xe8, +0xf0, +0x9f8, +0xa00 are read by the once predicate but
  never written by the owner function (verified by grep of the owner
  disassembly); their writers are outside this packet.
- The big control `_M_dispose` 0x5f061b0 (cache teardown, 0x398
  bytes) is cited, not excerpted or modelled.
- The +0x80 header role and the 0x605e830 register helper noted in
  #3286 remain open.
- The {1,1} dispose path of the small control's temporary reference
  at 0x5f10b80 is present in the binary but not taken in the observed
  trace; it is recorded as such.
- Elem ctor's other callers (0x6002925, 0x6067a9f) and the
  once-helper's other 6 callers are not modelled here.

## Follow-up ground

The 10 init-only sites' later preset behavior; singleton 0x61be810's
other 8 callers; 0x5d54910 (do NOT submit without a consumer);
0x5d591d0 (do NOT submit); 0x5d4ed40/0x5d4f400 (need decomposition);
owning caller functions 0x5d6da20..0x5d6ee3c, 0x5d6ef60..0x5d6faa0,
0x5d8479c..0x5d85475, 0x5d878f0..0x5d887b0; 252 acquire callers type
code 0x34; stats-emit slot-0xe8 callee + caller 0x5d7e339; big
_M_dispose 0x5f061b0 internals; +0xe8/+0xf0/+0x9f8/+0xa00 writers.

## Environment

This VM has no cargo/rustc, no git-lfs, no Ghidra/Java. All evidence
was produced with objdump and deterministic Python against the
materialized node #115 binary.
