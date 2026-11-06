# RE-001: pin node #115 canonical lea sites with the SystemClockWrapper slot-24 identity

Task: RE-001. Target: node #115 binary `work/hl-node-115.bin`,
SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
(the digest in `provenance/artifacts.json`).

## Bounded question

#3322 pinned the lazy resolver 0x5f074e0 and its canonical
chain-walk continuation 0x5d4b100, and left open: what are
the four `lea` sites that take the canonical's address for,
and who reads the second canonical slot at 0x64cde48? This
packet pins, end to end:

- the identity of the canonical: it is virtual slot 24
  (offset 0xc0) of the `rocksdb::SystemClockWrapper` vtable
  at 0x64cdd88, installed at 0x64cde48 by a RELATIVE record
  (and in the GOT slot 0x64ed3e8). Its typeinfo is
  `N7rocksdb18SystemClockWrapperE` at 0x972140.
- the four lea sites: each host routine unrolls the
  canonical's chain walk inline instead of calling it,
  comparing each level's vtable slot 24 against the
  canonical and dispatching to the first non-canonical
  level's slot 24, or to the terminal level's slot 24 when
  every compared level matches.
- the reader of 0x64cde48: no instruction in the node
  binary loads that address itself. The slot is read only
  through virtual dispatch at vtable offset 0xc0 on a
  SystemClockWrapper object — by the resolver, the
  canonical's own recursion, and the four lea sites.
  The vtable itself is installed by five small routines
  that `lea` its header 0x64cdd78, add 0x10, and store the
  result as the object's vptr.
- the override that makes the probe meaningful:
  `rocksdb::EmulatedSystemClock` (vtable 0x64d1650) shares
  the wrapper's slots 2..13, 15..18 and 25 but overrides
  slot 24 with 0x6025eb0, which answers from its own node
  (+0x48 flag, +0x30 value, +0x40 scaled add) or recurses
  down the chain. A chain of plain wrappers resolves
  through the canonical; a chain reaching an emulated clock
  resolves through 0x6025eb0.

## The four sites

The walk rule is identical in all four and in the canonical
itself: compare each level's slot 24 against the canonical;
the first mismatch has THAT slot called with (bool_out,
node, value_out); all matching advances one more node and
calls ITS slot 24 unconditionally. The slot-24 contract is
(bool_out, node, value_out), where bool_out is a
Status-shaped triple {u32 code, u16 code2, ptr}.

- site A 0x5dc9d70..0x5dca807 (11 compared, 12th called).
  Pre-walk: a SIMD sum of the +0x10 field over the pointer
  range [*(arg8+0xa98), *(arg8+0xa98)+8). Chain head
  *(arg+8)+0x210. Dispatch args: rdi = bool_out at
  -0xd0(%rbp), rdx = ptr_out at -0xd8(%rbp). First use:
  bool nonzero goes to 0x5dca750; otherwise the pointer is
  stored to -0x110(%rbp) and *(arg+0x38) nonzero goes to
  0x5dca6f8. Callers: 0x5dcb760..0x5dcb7ff,
  0x5dcb8c0..0x5dcba7f.
- site B 0x5e18d20..0x5e19117 (9 compared, 10th called).
  Entry gate: *(obj+0x270) byte 0, *(obj+0x271) byte 3,
  *(obj+0x438) nonzero, (+0x1068 - +0x1060) > 0x38,
  *(obj+0x10e0) byte 0. Chain head *(obj+0x240). Dispatch
  args: rdi = bool_out at 0x30(%rsp), rdx = ptr_out at
  0x20(%rsp). First use: bool nonzero or ptr_out <
  *(obj+0x438) goes to 0x5e19038; otherwise ptr_out -=
  *(obj+0x438) >> 1. Caller: 0x5e19290..0x5e19480.
- site C 0x5f7d7d0..0x5f7de6e (11 compared, 12th called).
  Prologue: *(arg1+0xc88) zeroed when set; *(arg1+0xd20)
  synced to *(arg1+0xd18) when they differ. Chain head
  *(arg2+0x210). Dispatch args: rdi = bool_out at
  0x50(%rsp), rdx = ptr_out at 0x38(%rsp). First use: bool
  nonzero or ptr_out < arg3 goes to 0x5f7daec; otherwise
  ptr_out -= arg3. Caller: 0x5f7e420..0x5f7edd7.
- site D 0x5f865d0..0x5f87065 (11 compared, 12th called).
  Pre-walk: a stack config is built (1 at -0x68(%rbp), 0
  at -0x60/-0x58, 1.0f at -0x50, 0 at -0x48/-0x40).
  Chain head is arg4. Dispatch args: rdi = bool_out at
  -0x100(%rbp), rdx = ptr_out at -0x128(%rbp). First use:
  bool nonzero goes to 0x5f86fcc; otherwise the pointer is
  stored to -0x1a0(%rbp) and the pair iteration begins.
  Caller: 0x5f870a0..0x5f87e4a.

The host functions' tails after the first use
(shared_ptr releases, vector push-backs, loops) are cited
with their callees in the excerpts, not modeled; the
packet's bounded behavior ends at the dispatch and its
first use.

## The SystemClockWrapper vtable

0x64cdd88, 26 slots, from the RELATIVE records. Slot 24
(0x64cde48) is the canonical 0x5d4b100. Slots 0, 1 and 14
hold no RELATIVE record (null); the rest are pinned in
records.json. Typeinfo pointer at 0x64cdd80 ->
0x64cd960, name `N7rocksdb18SystemClockWrapperE` at
0x972140; offset-to-top at 0x64cdd78 is 0.

## The EmulatedSystemClock vtable

0x64d1650, 26 slots. Slots 2..13, 15..18 and 25 are
identical to the wrapper's; slots 0, 1, 14, 19..24 are
overridden. Slot 24 (0x64d1710) is 0x6025eb0, whose
behavior is modeled: it zeroes the out triple; when the
node's +0x48 flag is set, value_out = *(node+0x30) and a
scaled add of *(node+0x40) runs
(value += ((0x431bde82d7b634db * v40 as signed 128-bit >>
64) >> 18) - sign(v40)); when the flag is clear it
recurses to *(node+0x20) with a temp triple, merges it
into out, then runs the scaled add when the merged code
is 0. Slots 0-1 (0x6029110, 0x6029620) are the two
wrapper-vtable installers below.

## The vtable installers

Five routines install the wrapper vtable by `lea` of its
header 0x64cdd78, `add $0x10`, and storing the result as
the object's vptr — no code in the binary takes the
vtable address 0x64cdd88 directly:

- 0x5fd0090..0x5fd0178 (called from 0x6029390..0x60294f5)
- 0x6029110..0x602922b (EmulatedSystemClock vtable slot 0,
  held at 0x64d1650)
- 0x6029230..0x602934b (called from 0x602934c..0x6029383)
- 0x6029500..0x602961b (no direct caller)
- 0x6029620..0x602973b (EmulatedSystemClock vtable slot 1,
  held at 0x64d1658)

## The entry installers

Three 0x2d-byte thunks install the FactoryEntry vtables
used by RegisterBuiltinEnvs / RegisterBuiltinSystemClocks:

- 0x5fcc5d0..0x5fcc5fd installs 0x64cd9d0 (ObjectLibrary
  ::Entry; its address is taken at 0x5fd280c in
  0x5fd27c0..0x5fd297f)
- 0x5fcc600..0x5fcc62d installs 0x64cd9e0 (address taken
  at 0x5fd288f in the same function)
- 0x5fcc630..0x5fcc65d installs 0x64cd9f0 (address taken
  at 0x5fd2124 in 0x5fd20d0..0x5fd241d)

Each thunk: mode 0 (edx == 0) installs its vtable at
(%rdi); mode 1 (edx == 1) stores rsi at (%rdi); any other
mode returns 0 unchanged.

## What this packet contains

- `site_a.txt`, `site_b.txt`, `site_c.txt`, `site_d.txt`:
  whole-function verbatim excerpts of the four lea-site
  hosts.
- `canonical.txt`, `resolver.txt`: re-shipped
  byte-identical from #3322 (SHA-256 pinned in
  records.json and checked by verify.py).
- `vtable_install_1.txt` .. `vtable_install_5.txt`:
  whole-function verbatim excerpts of the installers.
- `entry_install_1.txt` .. `entry_install_3.txt`:
  whole-function verbatim excerpts of the entry thunks.
- `frames.txt`: the 14 FDE ranges.
- `callers.tsv`: 15 rows — every direct call, tail jump
  and lea reference for the pinned routines, with the
  smallest enclosing FDE as the caller.
- `relocations.txt`: 30 RELATIVE records — the wrapper
  vtable header + slots, the FactoryEntry vtable headers,
  the GOT canonical slot.
- `records.json`: semantic records only — the dispatch
  rule, the two vtable slot tables, the site depths and
  gates, the installer forms, the census, the typeinfo
  literals, the open unknowns. No per-instruction
  mnemonic list: instruction-level detail lives only in
  the raw excerpt text files, kept verbatim and
  whole-function.
- `verify.py`, `census.py`, `export_excerpts.py` in the
  packet. The objdump command recorded here is
  `objdump -d --start-address=<start>
  --stop-address=<stop> work/hl-node-115.bin`.
  The mnemonics in the excerpts (endbr64 included) are
  genuine instructions present in the target binary, not
  placeholders.

## Verification

`python3 research/work-items/RE-001-canonical-lea-sites-115/verify.py`
reports ALL CHECKS PASSED: digest, manifest (22 files),
excerpts (14 windows), 28 spot instructions byte-for-byte
vs fresh objdump and the raw binary (including 3 seeded
random gate spots — 0x5dc9f4b, 0x5e18da7, 0x5f8674c),
frames, relocations, 6 literals, census (15 rows),
semantic records re-derived, model tests.

`python3 tests/test_canonical_lea_sites_115.py` — 172
checks, 0 failed (run directly, pytest is not installed
on this VM).

## Open unknowns

- Why the SystemClockWrapper vtable's slots 0, 1 and 14
  are null while the subclass EmulatedSystemClock fills
  slots 0-1 with its wrapper-installing destructors and
  slot 14 with 0x60257a0: recorded as observed, not
  explained.
- What the four lea-site host functions do after the
  first use of the dispatch result: their tails are cited
  with callees in the excerpts, not modeled.
- Which of the wrapper vtable's other slot functions each
  implement: only their addresses and FDE ranges are
  pinned here.
- The exact roles of the five vtable installers beyond
  the shared vptr install (copy vs move vs destructor):
  V2/V5 are EmulatedSystemClock vtable slots 0-1; V1/V3/V4
  have one direct caller each or none, and their field
  copies/releases are in the excerpts, not modeled.
- The qword copies of the canonical address at file
  offsets 0x10f9f0 and 0x15d270 sit inside .eh_frame data,
  not code: no instruction references them.
- The entry thunks' mode-1 arm stores rsi verbatim;
  which caller passes what pointer there is not traced.

## Environment limits

This VM has no cargo/rustc, no git-lfs and no Ghidra/Java,
so no Rust build or make verify/test run is claimed. The
host-function tails, the wrapper vtable's other slot
functions, and the entry thunks' mode-1 callers are cited
by contract, not re-implemented from a body this VM cannot
execute.
