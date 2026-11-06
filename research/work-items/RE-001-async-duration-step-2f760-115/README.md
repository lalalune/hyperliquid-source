# RE-001: map node #115 async duration step 0x5a2f760

Task ID: RE-001. Bounded question: what does the whole routine at
0x5a2f760 in the node #115 binary do, end to end — how does its
tag byte dispatch, what exactly does the tag-0 arm's f64-to-
Duration conversion compute and when does it panic, and what do
the predicate, release and guard arms do with the object?

## Evidence and binding

- Target: node #115, `work/hl-node-115.bin`, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  matching the `artifacts/node/115/hl-node` entry in
  `provenance/artifacts.json`.
- Excerpts: `main.txt` is the whole routine body, produced
  verbatim by `objdump -d --start-address=0x5a2f760
  --stop-address=0x5a2fa70 work/hl-node-115.bin` (FDE range
  0x5a2f760..0x5a2fa70, 784 bytes). `formatter.txt` is the
  error-kind Display shim at 0x1689370, `guards.txt` the two
  resume-guard shims at 0x1681e60 and 0x1681e80, and `builder.txt`
  the panic payload builder at 0x1680e80. `export_excerpts.py`
  regenerates all four.
- Instruction-level detail lives only in those verbatim excerpt
  text files. `records.json` holds semantic records only — no
  per-instruction mnemonic list. verify.py checks every excerpt
  instruction byte-for-byte against the raw binary.
- Frames: `frames.txt` carries the FDE lines for the routine and
  its three distinct caller functions.
- Census: `census.py` scans the executable LOAD segment
  exhaustively for E8/E9 sites targeting this routine and
  confirms each candidate with objdump; `callers.tsv` records
  the result. The routine has exactly 3 direct calls, 0 tail
  jumps, 0 stored qwords, 0 RELATIVE addends.
- Relocations: `relocations.txt` carries the RELATIVE records
  for every indirect-call slot and static-record slot this
  packet relies on; verify.py re-derives each target from a
  fresh relocation dump.
- Verification: `verify.py` re-checks the digest, the provenance
  entry, the manifest, excerpt regeneration byte-for-byte from a
  fresh objdump run, every excerpt instruction byte-for-byte
  against the raw binary, spot instructions, the FDE ranges, the
  relocation records, the jump-table entries recomputed from
  the binary, the panic and guard message bytes and the three
  location records recomputed from the binary, census
  consistency including per-site caller-function checks, the
  semantic records, and the model tests. It prints
  ALL CHECKS PASSED.

## Object layout and dispatch

The routine takes the object in rdi and a second argument in
rsi, which it keeps in r14 and forwards unchanged to the
predicate. The object layout, from the routine's own reads and
writes:

- +0x00: an f64, the seconds input of the tag-0 arm.
- +0x08..+0x78: a 0x70-byte value slot. Inside the constructed
  value, the byte at object +0x08 selects a destructor, the
  qword at object +0x10 is a counter pointer, and the field at
  object +0x18 is what the release routine takes.
- +0x78: the tag byte.

Entry zero-extends the tag byte and dispatches through the
table at 0x938f64 (4-byte signed offsets relative to the table
base). The four entries with targets inside this FDE are:
tag 0 -> 0x5a2f787 (conversion arm), tag 1 -> 0x5a2f9e8
(completion guard), tag 2 -> 0x5a2f9db (panicking guard),
tag 3 -> 0x5a2f976 (the predicate step, entered directly).

All three callers build the same layout before calling: each
stores an f64 at the object base, zeroes the byte at +0x78 and
passes a second argument in rsi (one caller, at 0x5a86a25,
stores the constant 5.0). The caller at 0x5a2f59e is the
four-state transition routine pinned by the open PR #3309
packet RE-001-async-value-transition-2f550-115, which cited
this routine only as its helper and left the helper's internals
out of scope; this packet pins exactly those internals and
nothing of the caller's own question.

## Tag 0: conversion and construction

The arm reads the f64 at +0x00 and converts it to (secs, nanos)
with a pure integer algorithm (transcribed band by band in
`tools/async_duration_step_2f760_115.py`):

- A `ucomisd` against 0.0 sends every negative value (including
  -inf and negative subnormals) and every NaN to the panic exit
  with error kind 0. -0.0 does not take that branch.
- Exponent below 0x3e0 (value below 2**-31, including zero and
  positive subnormals): (0, 0).
- 0x3e0 <= exponent < 0x3ff: secs 0; nanos is
  round-to-nearest-even(value * 1e9) computed on a 128-bit
  scaled-mantissa product; a rounded nanos of exactly 1e9
  becomes secs 1, nanos 0.
- 0x3ff <= exponent < 0x433: secs from the mantissa shift;
  nanos is round-to-nearest-even(fraction * 1e9), with the
  guard bit at product bit 51, the sticky bits under the
  0x000fffffffffffe00 mask and the result's low bit as the
  ties-to-even input; a rounded nanos of exactly 1e9 carries
  1 into secs.
- 0x433 <= exponent < 0x43f: the value is already an integer;
  secs = mantissa << (exponent - 0x433), nanos 0.
- Exponent >= 0x43f (value >= 2**64, including +inf): the
  panic exit with error kind 1.

The model tests prove the transcription equal to the exact
rational spec — the split of round-to-nearest-even(value * 1e9)
— over every band boundary, directed exact-tie mantissas and
tens of thousands of random bit patterns per band.

The panic exit (0x5a2fa24) stores the kind byte on the stack,
builds the single format argument {&kind, formatter 0x1689370}
and calls the payload builder 0x1680e80 (slot 0x64df6b8) with
the location record at 0x64b6f80 — file
`/rustc/59807616e1fa2540724bfbac14d7976d7e4a3860/library/core/src/time.rs`
(relocated file pointer, length 72), line 962, column 23 —
followed by `ud2`. The formatter (excerpted in full in
`formatter.txt`) writes, for kind 1, "cannot convert float
seconds to Duration: value is either too big or NaN" (72 bytes
at 0x479122) and otherwise "cannot convert float seconds to
Duration: value is negative" (59 bytes at 0x4790e7), through
the write shim at 0x167fa70. So a NaN input reports through
the kind-0 arm even though its message names the negative
case; that is the binary's own routing, recorded as found.

On success the arm calls the constructor at 0x5cf2150 (slot
0x64e13a0) with (out = rsp+0x20, secs, nanos, and the static
record at 0x64b81a8 in rcx — file `base/src/lu.rs`, length 14,
line 75, column 5), then copies the 0x70-byte value it built
into obj+0x08..obj+0x78 (seven 16-byte vector moves, via a
scratch copy) and falls into the predicate step.

## Predicate step, false path, guards

The predicate step (0x5a2f976, also the tag-3 entry) calls
0x5cf2d30 (slot 0x64e0858) with (obj+0x08, the routine's second
argument):

- True: the shared exit stores tag 3 at obj+0x78 and returns
  the predicate's byte in eax.
- False: the counter behind the pointer at obj+0x10 is
  decremented with `lock decq`; only when it reaches zero, the
  destructor the value's first byte selects is called with
  rdi = obj+0x10 — byte 0 selects 0x5ce86d0 (slot 0x64dfdb8),
  nonzero selects 0x5ce8da0 (slot 0x64dfdc8). The release
  routine 0x5a52490 is then called on obj+0x18, the shared exit
  stores tag 1, and the predicate's 0 is returned.

Tag 1 calls the completion guard 0x1681e60 (slot 0x64e1368)
with rdi = the static record at 0x64b81c0 (file
`base/src/lu.rs`, length 14, line 74, column 57); the guard
panics with "`async fn` resumed after completion" (35 bytes at
0x46f2ed, passed to the payload builder with the pre-encoded
length 71 = 2*35 + 1) and does not return. Tag 2 calls the
panicking guard 0x1681e80 (slot 0x64e1360) with the same
record; it panics with "`async fn` resumed after panicking"
(34 bytes at 0x46f310, pre-encoded length 69) and does not
return — the completion-guard call that follows it in the
byte stream is reached only if the first guard returned.

Six landing pads close the FDE (transcribed literally in
`main.txt` order in records.json): they save the exception,
variously call the release 0x5a52490 on obj+0x18, call the pad
callee 0x1680cab (slot 0x64df4c0), or call the drop 0x5a423a0
on obj+0x08, write tag 2 at obj+0x78, and resume the unwind.
Which pad belongs to which call site is a property of the
LSDA, which this packet does not decode; the assignment is
therefore not claimed.

## Distinctness

This routine is the helper the #3309 packet
(RE-001-async-value-transition-2f550-115, open) cites as a
callee: that packet pins the caller's four-state transition
and explicitly leaves the helper's internal arithmetic out of
scope; the question here — the helper's tag dispatch, its
conversion decision table and its predicate/release exits —
is answered by no open PR and no merged work-item. The
conversion decision table also appears, inlined, in the
consensus timer body pinned by #3311
(RE-001-node115-consensus-timer-conversion): that packet pins
the timer routine 0x4eca5d0 and its own inputs (0.3 and
0.09999999999999999 through a GOT slot); the body here is a
different FDE, reached by direct calls, embedded in a tag
state machine #3311 does not contain, and its conversion arm
is only one of its four arms. The destructors 0x5ce86d0 and
0x5ce8da0 are the same pair #3309 records its caller
selecting between on its own false path; here the selection
is pinned from inside the routine that performs it.

## Not claimed

- The bodies of the constructor 0x5cf2150, the predicate
  0x5cf2d30, the destructors 0x5ce86d0/0x5ce8da0, the release
  0x5a52490, the drop 0x5a423a0 and the pad callee 0x1680cab;
  only their call sites, argument registers and observable
  order are pinned.
- What the constructed 0x70-byte value means beyond the three
  fields this routine itself reads back (flag byte, counter
  pointer, released field), what the predicate decides, or
  what the callers' second arguments denote.
- Whether the record at 0x64b81c0 serves the guards purely as
  a source Location or also as a state cell.
- Landing-pad to call-site assignment (the LSDA is not
  decoded), and any behaviour for tag bytes outside 0..3,
  which no writer in this routine produces.

## Model and tests

`tools/async_duration_step_2f760_115.py` models the routine:
`convert_f64_seconds` transcribes the conversion band by band,
and `step` models the tag state machine with the callees
recorded as ordered effect tuples. `tests/test_async_duration_
step_2f760_115.py` checks the conversion against exact rational
arithmetic (every band boundary, directed exact ties, random
sweeps per band, both panic kinds and their messages, -0.0),
and pins every step transition: tag 0 and tag 3, predicate
true and false, both destructor selections, the counter
surviving (no destructor call, release still runs), the
conversion panic preceding any effect, both guard messages,
and the unwind tag poison.
