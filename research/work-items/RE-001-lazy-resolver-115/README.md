# RE-001: pin node #115 lazy one-time resolver 0x5f074e0 with its once-helper call site in 0x5f0e890

Task: RE-001. Target: node #115 binary `work/hl-node-115.bin`,
SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
(the digest in `provenance/artifacts.json`).

## Bounded question

After the once decision 0x5f07490 runs on the owner object in
0x5f0e890, what does the resolver 0x5f074e0 called right after
it do to pin owner+0xcb8 exactly once: which chain it walks,
how the first non-canonical slot 0xc0 wins, when the value is
installed, and what the call-site gate is? This packet pins,
end to end:

- the call site in 0x5f0e890 (window 0x5f0ef1c..0x5f0ef60):
  the helper and the resolver run on the same object r13
  exactly when *(owner+0xc18) != 0 and not (*(owner+0xc60)
  != 0 and *(owner+0x30) != 0); the second combination jumps
  to 0x5f0f0a7 instead. +0xc60 is the small shared table and
  +0x30 the flag from #3304's small-install gate; the writer
  of +0xc18 is an open unknown (it sits in the +0xa60..+0xc38
  region the tail init zeroes in #3304 and is set later).
- the resolver 0x5f074e0 (0x123 bytes): owner+0xcb8 is read
  first and a value other than -1 returns at once; the chain
  head is owner+0xc70 (the pair {*(options+0x210),
  *(options+0x300)} from #3304); four levels are compared
  inline against the canonical 0x5d4b100 (GOT slot
  0x64ed3e8) and the fifth level's slot 0xc0 is called
  unconditionally; the winning slot is called with
  (bool_out at rsp+0x10, node, value_out at rsp+0x08) and
  also provides the owned heap pointer read at rsp+0x18;
  when the bool is false the value is installed into
  owner+0xcb8 with a lock cmpxchg against the -1 sentinel,
  when true nothing is installed; the owned pointer, when
  non-null, is freed with delete[] either way.
- the canonical continuation 0x5d4b100 (0x10c bytes): it
  advances past the node it was called on (the caller
  already found that node's slot canonical), compares eight
  more levels, and calls the ninth level's slot
  unconditionally, recursing into itself when that slot is
  canonical too. Two GOT slots hold it (0x64ed3e8, the one
  the resolver compares against, and 0x64cde48, whose reader
  was not found in the linear disassembly); four sites lea
  its address (0x5dc9e69, 0x5e18dbb, 0x5f7d83e, 0x5f8666a).
- the sentinel: owner+0xcb8 starts at -1, the low qword of
  the 16-byte constant at 0x456590 ({-1, 0}) installed by
  the owner-tail init in #3304.
- the once helper 0x5f07490 and its predicate 0x5f07300,
  re-shipped byte-identical from #3304, which pins the once
  decision itself (the predicate calls SkipListRep slot 15
  on both products and decides the resize from the 0.6
  factor; the helper latches owner+0xc68 to 1 only when the
  predicate returns true).

## A finding about the other once-helper call sites

The census for 0x5f07490 shows all seven call sites in one
place. Two of them never fire: in the tree-walk consumers
0x5fbcd50 and 0x5fbcfa0 the gate byte at frame+0x49 /
frame+0x89 is set to 0 by the prologue (`movb $0x0,
0x49(%rsp)` / `movb $0x0,0x89(%rsp)`) and the walk is
skipped while it is 0 (`cmpb $0x0,0x49(%rsp); je`). The
only calls between the prologue and the gate are the
0x5fbbc40/0x5fbbc50 accessor and the 0x5fbba60 Status
builder, neither of which writes the walker's stack frame,
and the map headers at frame+0x78 / frame+0xb8 are never
populated — so the once-helper calls at 0x5fbced8 and
0x5fbd180 inside those walks are unreachable in every call
path. The other five sites are live; this packet pins the
0x5f0ef46 one. Reachability of the three sites in
0x5f0f930 was not checked this cycle and is recorded as an
unknown, not as a claim.

## Evidence

- `resolver.txt`: the whole resolver 0x5f074e0..0x5f07603,
  verbatim.
- `canonical.txt`: the whole canonical continuation
  0x5d4b100..0x5d4b20c, verbatim.
- `callsite.txt`: the decision window 0x5f0ef1c..0x5f0ef60
  in 0x5f0e890, verbatim.
- `once_helper.txt`, `once_pred.txt`: re-shipped
  byte-identical from the RE-001-owner-tail-phases-115
  packet (#3304); the SHA-256 values are pinned in
  MANIFEST.sha256 and re-checked by verify.py against a
  fresh objdump run.
- `frames.txt`: the five FDEs (resolver, canonical,
  call-site function, helper, predicate).
- `callers.tsv`: 1331 rows — every direct call, tail jump
  and lea reference for the resolver, the canonical, the
  once helper and predicate, the call-site function, the
  sibling 0x5f0f930, the two tree-walk consumers, the
  shared-table-resize 0x5f0b420 and the release helper
  0x5d350c0 (1273 calls, 25 tail jumps, matching #3304).
- `relocations.txt`: the RELATIVE record installing the
  canonical in GOT slot 0x64ed3e8.
- `records.json`: semantic records only — the resolver,
  canonical, call-site, once and GOT records, the census,
  the sentinel literal and the open unknowns. No
  per-instruction mnemonic list: instruction-level detail
  lives only in the verbatim excerpt files.
- `verify.py`, `export_excerpts.py`, `census.py`: the
  packet's own runnable checks, exporter and census.

The mnemonics in the excerpts (endbr64 included) are
genuine instructions present in the target binary, not
placeholders.

## Model and tests

`tools/lazy_resolver_115.py` models the resolver, the
canonical walk, the call-site gate and the chain helpers;
`tests/test_lazy_resolver_115.py` runs 78 checks directly
(no pytest on this VM): the sentinel and early return,
a winner at each inline level 1..5 and deep levels 6, 13,
14, 15 and 23, the skip-cache bool, the owned-pointer
free, a two-thread race that installs exactly once, null
chain faults, all five call-site gate combinations, the
chain helpers and the pinned constants.

## Unknowns

- The node types in the +0xc70 chain and what their slot-24
  functions compute; the packet pins the resolver's walk
  and install, not the callees.
- The writer of owner+0xc18, the call-site gate flag.
- The writers of owner+0x30 and owner+0xc60 beyond what
  #3304 pins for the small-install gate.
- The roles of the four lea sites that take the canonical's
  address, and the reader of the second canonical GOT slot
  0x64cde48.
- Reachability of the three once-helper sites in 0x5f0f930.
- The full semantics of 0x5f0e890 beyond the decision
  window (the hash-probe loop and the 0x5f0f0a7 / 0x5f0f188
  branches).

## Environment limits

This VM has no cargo/rustc, no git-lfs and no Ghidra/Java,
so `make verify` / `make test` / `make catalogue-check`
cannot run here; the packet's own verify.py and the model
tests are the checks run. The disassembly evidence was
verified byte-for-byte against the real node #115 binary
(digest above) with fresh objdump runs.
