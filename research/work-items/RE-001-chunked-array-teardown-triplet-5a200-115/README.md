# RE-001: map node #115 chunked array teardown triplet 0x5d5a200 / 0x5d5a270 / 0x5d5a2e0 with its shared owner sequence and twelve callers

Bounded question: what do node #115 routines 0x5d5a200, 0x5d5a270 and
0x5d5a2e0 (each FDE 101 bytes) do to the holder in rdi, end to end,
and how are the three related to each other and to their callers?

## Answer

They are one family of chunked array teardowns with the same shape:
each frees a run of fixed-size chunk blocks pointed to by slots on the
holder itself, then frees the inner object the holder points at, sized
by a qword count on the holder. Each pushes r12/rbp/rbx, reserves no
stack, and performs no canary check.

Inner gate. The holder in rdi points at an inner object:
inner = [holder+0x00]. A null inner returns plainly with nothing
freed — neither the chunk phase nor the inner free runs, even though
the chunk slots live on the holder, not on the inner object. The outer
holder itself is never freed in any path.

Chunk phase. The holder carries a chunk-pointer slot range: the cursor
starts at [holder+0x28] and the bound base is [holder+0x48]. The loop
runs while the cursor is below [holder+0x48] + 8 (unsigned comparison),
stepping 8, so the slot at [holder+0x48] itself is included. Per slot
the pointer is freed with a sized delete through the _ZdlPvm PLT at
0x63f0d80: exactly 0x200 bytes for 0x5d5a200 and 0x5d5a2e0, exactly
0x1f8 bytes for 0x5d5a270. There is no null test on slot pointers:
every slot's pointer is passed to the sized delete unconditionally,
and the cursor is advanced before the call, so the frees follow slot
order. When the cursor is already at or past the bound at entry, the
loop is skipped outright and control reaches the exit with rdi still
holding the inner pointer (the reload exists only for the
loop-taken path).

Exit. Each routine tail-jumps to the sized-delete PLT freeing the
inner object at ([holder+0x00], [holder+0x08] * 8): the count qword at
holder+0x08 is shifted left by 3 to form the byte size. This exit runs
whenever the inner object is non-null, whether the loop ran or was
skipped, and there is no null test on the inner pointer at this point
either — it is already known non-null from the entry gate.

How the three differ. 0x5d5a200 and 0x5d5a2e0 are instruction-identical
modulo their addresses and call displacements (verified by normalizing
branch-target annotations in the two whole-function excerpts: zero
remaining differences across all 32 instruction lines each).
0x5d5a270 differs from both only in its chunk size, 0x1f8 instead of
0x200. They are kept as three distinct routines, not merged, because
their caller sets differ: 0x5d5a200 has three standalone callers the
other two lack (see below). Why two identical routines exist for
distinct holders is recorded as unknown, not guessed.

The owner sequence — the behavior that makes this one work item rather
than three copies of one claim. The three routines are called in the
fixed order 0x5d5a2e0, then 0x5d5a270, then 0x5d5a200, by the same
owners, with rdi from three distinct rbx-relative holders at offsets
0xb20, 0xad0 and 0xa68 respectively. That sequence occurs three times:
once in 0x5d8479c..0x5d85475 (sites 0x5d84b73, 0x5d84b7f, 0x5d84b8b)
and twice in 0x5d878f0..0x5d887b0 (sites 0x5d87efb, 0x5d87f07,
0x5d87f13 and 0x5d88643, 0x5d8864f, 0x5d8865b). So the owning objects
tear down three chunked members in one fixed order — the pinned
end-to-end behavior of this packet.

Consumers (executable-LOAD-segment exhaustive E8/E9 scan with objdump
confirmation, reproduced by the packet's census.py and re-run inside
verify.py): exactly 12 direct calls + 0 tail jumps in total —
0x5d5a200: 6 calls across 4 caller FDEs; 0x5d5a270: 3 calls across 2
caller FDEs; 0x5d5a2e0: 3 calls across 2 caller FDEs (see callers.tsv
for the site list and the rdi source at each site). The three
standalone 0x5d5a200 callers pass rdi from lea 0x1a8(%rbx) at
0x6135281 and lea 0x78(%rbx) at 0x6135602 (both in
0x6135242..0x61356f3) and lea 0x78(%rbx) at 0x6135f08 (in
0x6135f04..0x613602d); they are not part of the owner sequence.
0 stored qwords in a full-file 8-byte scan, 0 RELATIVE relocations
for any of the three — reached only by code, never by data. What any
caller does with a holder before or after the call is not claimed here.

Relation to neighbouring work: the same chunked shape as the
0x5d58fb0 teardown (#2732: chunk slots at holder+0x28/+0x48, 0x200-byte
chunks, inner free sized by holder+0x08), but this packet pins a
different fact — the three-member teardown sequence of shared owners,
including the 0x1f8-sized middle member and the extra standalone
0x5d5a200 callers — not a restatement of #2732's single routine.
Distinct from the nested array teardown 0x5d58f10 (#2729: an inner
vector of 8-byte pointers with a per-element string dispose) and from
the list teardowns 0x5d596f0 (#2728) and 0x5d59780 (#2725: linked
chains, holder never freed).

## Evidence notes

Bound to the node #115 artifact in provenance/artifacts.json
(artifacts/node/115/hl-node, SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301,
materialized locally as work/hl-node-115.bin with the same digest).

Excerpt commands (run from the repository root; headers normalized to
the bare binary name only):
- objdump -d --start-address=0x5d5a200 --stop-address=0x5d5a265 work/hl-node-115.bin
- objdump -d --start-address=0x5d5a270 --stop-address=0x5d5a2d5 work/hl-node-115.bin
- objdump -d --start-address=0x5d5a2e0 --stop-address=0x5d5a345 work/hl-node-115.bin
- objdump -d --start-address=<site> --stop-address=<site+32> work/hl-node-115.bin for each of the 12 sites
- readelf --debug-dump=frames work/hl-node-115.bin for the FDE lines

Instruction-level detail lives only in the raw disassembly excerpt
text files (main_5a200.txt, main_5a270.txt, main_5a2e0.txt,
caller_sites.txt), kept verbatim and whole-function. The packet's JSON
(records.json) carries semantic records only — no per-instruction
list. Mnemonics such as `endbr64` in the excerpts are genuine
instructions present in the target binary, not placeholders; verify.py
checks every excerpt line byte-for-byte against the raw binary and
regenerates every excerpt from a fresh objdump run.

The packet additionally carries its own runnable verification code:
verify.py (the checker behind "ALL CHECKS PASSED"), export_excerpts.py
(the generator of the excerpts) and census.py (the caller census),
all committed inside this directory.

Unknowns, recorded explicitly rather than filled in: what the
holder+0x08 count counts at the source level (only the byte size
[holder+0x08] * 8 is pinned); why two instruction-identical routines
exist for distinct holders; the source-level type of the holders and
of the chunk blocks (only sizes and offsets are pinned); what any
caller does with a holder before or after the call. Fields on the
holder other than +0x00, +0x08, +0x28 and +0x48 are never read, and
their role is not claimed.
