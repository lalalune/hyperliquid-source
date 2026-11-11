# RE-001: map node #115 record-loop teardown 0x5d59510 with its eleven per-record fields and two callers

Bounded question: what does node #115 routine 0x5d59510 (FDE
0x5d59510..0x5d596e5, 469 bytes) do to the holder in rdi, end to end?

## Answer

It is a record-loop teardown followed by a buffer exit, not a
destructor: it walks a vector of fixed-stride records, disposing
eleven string fields in each record, then conditionally frees the
record buffer — but it never frees the holder itself, writes nothing
back to the holder or the records, and performs no canary check. It
pushes r12/rbp/rbx and reserves no stack.

Holder layout. The holder is a vector: begin at +0x00, end at +0x08,
capacity end at +0x10. The end is loaded once at entry into rbp;
when begin equals end the loop is skipped entirely and control goes
straight to the buffer exit.

Per record. Records are 0x1d8 bytes, walked from begin to the
loaded end. Each record carries eleven string fields, disposed in
this exact order (pointer offset / capacity offset):

1. +0x1b0 / +0x1c0
2. +0x190 / +0x1a0
3. +0x170 / +0x180
4. +0x150 / +0x160
5. +0x130 / +0x140
6. +0xd0 / +0xe0
7. +0xb0 / +0xc0
8. +0x80 / +0x90
9. +0x60 / +0x70
10. +0x20 / +0x30
11. +0x00 / +0x10

Every field follows the same short-form rule: when the pointer
equals the record base plus the capacity offset (the address of
its own capacity slot), nothing is freed; otherwise a sized delete
of (pointer, capacity + 1) runs through the _ZdlPvm PLT at
0x63f0d80. The eleventh field is the one ordering detail worth
pinning: the cursor is advanced by 0x1d8 before its delete call
(the short path advances the cursor the same way), so the free
order is unchanged — the next record is only processed after that
call — but a reader tracing registers will see the new cursor
already in place at the call.

Buffer exit. The begin is reloaded from holder+0x00. A null begin
returns plainly. Otherwise the routine tail-jumps to the
sized-delete PLT freeing (begin, [holder+0x10] - begin). The end
slot (+0x08) is not reset, the begin slot is not cleared, and no
call other than the sized-delete PLT occurs anywhere in the
routine.

Consumers (executable-LOAD-segment exhaustive E8/E9 scan with objdump
confirmation, reproduced by the packet's census.py and re-run inside
verify.py): exactly 2 direct calls + 0 tail jumps across 2 caller
FDEs (see callers.tsv); 0 stored qwords in a full-file 8-byte scan,
0 RELATIVE relocations — reached only by code, never by data. The
first caller passes rdi from 0x68(%rsp) immediately before its call
site at 0x5d7b494; the second passes rdi from 0x48(%rsp) before its
call site at 0x5e85068. What either caller does with the holder
before or after the call is not claimed here.

Relation to neighbouring work: distinct from the record teardown
0x5d593f0 (stride 0x130, four fields, covered by #2724) and from the
record loop inside the object teardown 0x5d56f50 (stride 0x218,
covered by #2720) — this routine has its own stride and its own
eleven-field set. It is also distinct from the adjacent linked-list
teardowns 0x5d596f0 and 0x5d59780, which walk a pointer chain
rather than a fixed-stride array.

## Evidence notes

The raw excerpts in this packet are verbatim objdump output, kept
whole-function; the objdump command that produced each file is
recorded in export_excerpts.py. Instruction text such as `endbr64`
at the routine entry is a genuine instruction present in the target
binary, not a placeholder. The packet JSON holds semantic records
only, not a per-instruction list.

## Unknowns (not claimed)

- What the records hold beyond their eleven pointer/capacity
  pairs; they are recorded as observed pairs only.
- What either caller function does with the holder before or after
  this call; only the call sites and their FDEs are recorded.
- Behaviour on a malformed range (an end that does not delimit
  whole 0x1d8-byte records, or a non-null begin with a capacity end
  below it); the model requires a well-formed range.
- Behaviour when the range changes during disposal; the end is
  loaded once at entry, so the model treats the range as fixed.

## Verification

Run from the repository root:

    python3 research/work-items/RE-001-record-loop-teardown-59510-115/verify.py
    python3 research/work-items/RE-001-record-loop-teardown-59510-115/census.py

The checker binds the binary SHA-256 to provenance/artifacts.json,
regenerates every excerpt byte-for-byte from fresh objdump runs,
checks every main.txt line against the raw binary, re-runs the
caller census, and invokes the model tests in
tests/test_record_loop_teardown_59510_115.py.
