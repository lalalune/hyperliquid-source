# RE-001: map node #115 record-vector destructor 0x5d59e00 with its thirteen per-record phases and two callers

Bounded question: what does node #115 routine 0x5d59e00 (FDE
0x5d59e00..0x5d5a1fe, 1022 bytes) do to the vector in rdi, end to
end, and who calls it?

## Answer

It destroys a vector of 0x300-byte records and then frees the
vector's own buffer. The holder in rdi is a vector triple: begin at
holder+0x00, end at holder+0x08, capacity end at holder+0x10. The
record loop walks begin to end in steps of 0x300; an empty range
skips the loop outright. Each record runs thirteen phases in a
fixed order (below), then the routine advances to the next record.
The holder itself is never freed. The routine pushes
r15/r14/r13/r12/rbp/rbx, reserves 0x18 stack bytes, and performs
no canary check.

Exit. After the loop (or the empty-range skip), the routine frees
the outer buffer with a sized delete of ([holder+0x00],
[holder+0x10] - [holder+0x00]) through the _ZdlPvm PLT at
0x63f0d80, tail-jumped. A null begin returns plainly with nothing
freed; the empty-range entry path tests begin the same way before
its tail-jump. So the observable contract is: destroy every
record in [begin, end), then free the buffer span, never the
holder.

Per-record phases, in order. All sizes are byte sizes passed to
the sized-delete PLT unless stated otherwise.

1. Inlined refcounted release at record+0x2f8. The member holds a
   control-block pointer; null skips. Otherwise the count at
   control+0x08 is compared against the sentinel 0x100000001:
   equal enters the cold block at 0x5d5a1d0, which zeroes
   control+0x08 and calls virtual dispatch slots 0x10 then 0x18
   on the control block. Otherwise the count is decremented —
   plain store, or atomic lock xadd when the flag byte at
   0x64ed290 is zero — and a count that was 1 calls the release
   helper at 0x5d35070.
2. The same inlined refcounted release at record+0x2e8 (cold
   block at 0x5d5a190).
3. String vector teardown at record+0x2c8/+0x2d0/+0x2d8. The
   vector holds 0x28-byte elements; each element's string pointer
   is at element+0x00 with its capacity at element+0x10. The
   short-form rule applies: a pointer equal to element+0x10
   frees nothing, else a sized delete of (pointer, capacity + 1)
   runs. Elements advance by 0x28. After the loop the buffer is
   freed with a sized delete of ([record+0x2c8], [record+0x2d8] -
   [record+0x2c8]) when begin is non-null.
4. Refcounted-pointer release at record+0x2c0 through helper
   0x5d350c0; null skips.
5. The same inlined refcounted release at record+0x298 (cold
   block at 0x5d5a1b0).
6. Refcounted-pointer release at record+0x210 through helper
   0x5d350c0; null skips.
7. Refcounted-pointer release at record+0x1f8 through helper
   0x5d350c0; null skips.
8. Refcounted-pointer release at record+0x1d8 through helper
   0x5d350c0; null skips.
9. Shared-pointer vector teardown at record+0x138/+0x140/+0x148.
   The vector holds 0x10-byte elements; each element's control
   block is at element+0x08. Null elements are skipped. Otherwise
   the same release shape as phases 1/2/5 applies per element
   (sentinel cold block at 0x5d5a0e8, count of 1 calls helper
   0x5d35070, other counts decrement plain or atomic by the flag
   byte). After the loop the buffer is freed with a sized delete
   of ([record+0x138], [record+0x148] - [record+0x138]) when
   begin is non-null.
10. Refcounted-pointer release at record+0x130 through helper
    0x5d350c0; null skips.
11. Plain buffer free at record+0xb0/+0xc0: sized delete of
    ([record+0xb0], [record+0xc0] - [record+0xb0]) when non-null.
12. Plain buffer free at record+0x70/+0x80: sized delete of
    ([record+0x70], [record+0x80] - [record+0x70]) when non-null.
13. Refcounted-pointer release at record+0x58 through helper
    0x5d350c0; null skips. Then the next record, or the exit.

Callee notes (verified, not merely claimed). Helper 0x5d35070:
virtual dispatch slot 0x10 on the control block, then the weak
count at control+0x0c decremented (plain or atomic by the same
flag byte), tail-jumping to virtual dispatch slot 0x18 when
last. Helper 0x5d350c0: the count at pointer+0x08 is compared
against the same 0x100000001 sentinel; the sentinel path zeroes
+0x08 and enters virtual dispatch slots 0x10/0x18, a count of 1
enters the destroy path, other counts decrement +0x08. The
destroy-path instructions inside 0x5d350c0 beyond the sentinel
compare, the +0x08 zeroing and the dispatch entry are not pinned
here; only the helper's observable release contract is claimed.

Consumers (executable-LOAD-segment exhaustive E8/E9 scan with
objdump confirmation, reproduced by the packet's census.py and
re-run inside verify.py): exactly 2 direct calls + 0 tail jumps
— 0x5d713ab in 0x5d71370..0x5d713ed (rdi from mov 0x8(%rsp),
a stack slot whose contents are not pinned here) and 0x60cd66d
in 0x60cd610..0x60cd6e7 (rdi from lea 0x2e0(%rbx); that caller
first frees a 0x308-member buffer). 0 stored qwords in a
full-file 8-byte scan, 0 RELATIVE relocations — reached only by
code, never by data.

Relation to neighbouring work: this is the first packet in this
series to pin a whole multi-phase record destructor rather than
one teardown shape; its string-vector phase (phase 3) shares the
short-form string rule with the nested array teardown 0x5d58f10
(#2729) and the record-loop teardowns, but the thirteen-phase
record, the 0x300 stride and the outer vector buffer free are
pinned here only. It is not a restatement of any single-shape
teardown PR.

## Evidence notes

Bound to the node #115 artifact in provenance/artifacts.json
(artifacts/node/115/hl-node, SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301,
materialized locally as work/hl-node-115.bin with the same digest).

Excerpt commands (run from the repository root; headers normalized to
the bare binary name only):
- objdump -d --start-address=0x5d59e00 --stop-address=0x5d5a1fe work/hl-node-115.bin
- objdump -d --start-address=<site> --stop-address=<site+32> work/hl-node-115.bin for each of the 2 sites
- readelf --debug-dump=frames work/hl-node-115.bin for the FDE lines

Instruction-level detail lives only in the raw disassembly excerpt
text files (main.txt, caller_sites.txt), kept verbatim and
whole-function. The packet's JSON (records.json) carries semantic
records only — no per-instruction list. Mnemonics such as `endbr64`
in the excerpts are genuine instructions present in the target
binary, not placeholders; verify.py checks every excerpt line
byte-for-byte against the raw binary and regenerates every
excerpt from a fresh objdump run.

The packet additionally carries its own runnable verification code:
verify.py (the checker behind "ALL CHECKS PASSED"),
export_excerpts.py (the generator of the excerpts) and census.py
(the caller census), all committed inside this directory.

Unknowns, recorded explicitly rather than filled in: the
source-level types of the records and of every member (only sizes,
strides and offsets are pinned); what the 0x300-byte records
represent and what the callers do with a holder before or after
the call; the source meaning of the 0x100000001 sentinel beyond
the observed packed-count compare, and of the flag byte at
0x64ed290 beyond plain-vs-atomic selection; the destroy-path
instructions inside helper 0x5d350c0 beyond the sentinel compare,
the +0x08 zeroing and the dispatch entry; record fields outside
the thirteen phases are never read by this routine, and their
roles are not claimed.
