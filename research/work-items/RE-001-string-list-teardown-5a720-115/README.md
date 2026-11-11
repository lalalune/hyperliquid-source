# RE-001: map node #115 string-list teardown 0x5d5a720 with its two-string nodes, buffer clear and three callers

Bounded question: what does node #115 routine 0x5d5a720 (FDE
0x5d5a720..0x5d5a7e5, 197 bytes) do to the holder in rdi, end to
end, and who calls it?

## Answer

It destroys a holder's string-carrying linked list, then clears
and frees the holder's buffer. The holder itself is never freed.
The routine pushes r12/rbp/rbx, reserves no stack bytes, and
performs no canary check.

List phase. The list head lives at holder+0x10; a null head
skips the loop outright and the buffer phase still runs. Each
0x68-byte node runs, in order:

1. String A dispose at node+0x30 (capacity at node+0x40). The
   short-form rule applies: a pointer equal to node+0x40 frees
   nothing, else a sized delete of (pointer, capacity + 1) runs
   through the _ZdlPvm PLT at 0x63f0d80.
2. String B dispose at node+0x10 (capacity at node+0x20), under
   the same short-form rule and the same PLT.
3. Node free: a sized delete of exactly 0x68 through the same
   PLT.

The next pointer at node+0x00 is loaded before any of the
frees, so the loop follows it until null without touching freed
memory for the link. The two strings are disposed A-then-B in
every node; the node free follows both.

Buffer phase (always runs, even for an empty list). The buffer
span is (begin at holder+0x00, count at holder+0x08): memset
(begin, 0, count * 8) runs through the memset PLT at 0x63f0a90,
holder+0x10 and holder+0x18 are zeroed, and then, unless begin
equals holder+0x30, the buffer span is freed with a sized delete
of (begin, count * 8) through the _ZdlPvm PLT, tail-jumped. A
begin equal to holder+0x30 returns plainly with no buffer free.
The count field at holder+0x08 is not cleared and the begin
field is not cleared; only the two zeroed fields and the
conditional free are pinned.

Consumers (executable-LOAD-segment exhaustive E8/E9 scan with
objdump confirmation, reproduced by the packet's census.py and
re-run inside verify.py): exactly 3 direct calls + 0 tail jumps
— 0x5d849fb in 0x5d8479c..0x5d85475, 0x5d87cea and 0x5d88432 in
0x5d878f0..0x5d887b0 — and all three pass rdi from
lea 0x1318(%rbx), i.e. the same rbx-relative member in both
owning functions. 0 stored qwords in a full-file 8-byte scan,
0 RELATIVE relocations — reached only by code, never by data.

Relation to neighbouring work: this routine shares the holder
layout and the buffer tail (memset, zeroing of +0x10/+0x18, the
+0x30 begin comparison) with the plain list teardown 0x5d596f0
(#2728), but the per-node behavior pinned here is different:
0x68-byte nodes carrying two short-form strings, versus 0x18-byte
plain nodes with no payload disposal. The two-string node
disposal, the 0x68 node size and the three callers are pinned
here only; this is not a restatement of #2728.

## Evidence notes

Bound to the node #115 artifact in provenance/artifacts.json
(artifacts/node/115/hl-node, SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301,
materialized locally as work/hl-node-115.bin with the same digest).

Excerpt commands (run from the repository root; headers normalized to
the bare binary name only):
- objdump -d --start-address=0x5d5a720 --stop-address=0x5d5a7e5 work/hl-node-115.bin
- objdump -d --start-address=<site> --stop-address=<site+32> work/hl-node-115.bin for each of the 3 sites
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
source-level types of the holder, the list nodes and the two
strings per node (only sizes, strides and offsets are pinned);
the source meaning of holder+0x18 (zeroed in the buffer phase)
and of the holder+0x30 begin comparison beyond the observed
inline-storage-shaped test — only the comparison and the exact
free size are pinned; what the callers do with the holder before
or after the call, and what the list nodes represent; node fields
outside +0x00/+0x10/+0x20/+0x30/+0x40 are never read by this
routine, and their roles are not claimed; the null-begin
buffer-phase case: the code memsets and conditionally frees
through a null begin pointer when count is zero, and behavior
for a null begin with a nonzero count is not pinned and is not
modelled.
