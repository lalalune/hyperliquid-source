# RE-001: map node #115 record string-vector triple destructor 0x5d5ae50 with its sole cleanup caller

Bounded question: what does node #115 routine 0x5d5ae50 (FDE
0x5d5ae50..0x5d5afe8, 248 bytes) destroy, in what order, and
who calls it?

## Answer

It destroys a vector of 0x70-byte records and frees the
holder's own buffer span. It returns nothing. The routine
pushes r14, r13, r12, rbp and rbx, reserves no stack, and
performs no canary check.

Holder. rdi is the holder pointer: a vector triple with begin
at +0x00, end at +0x08 and capacity end at +0x10. The outer
loop walks records from begin to end in steps of 0x70; a begin
equal to end skips the loop.

Per record, in fixed order. Each record holds three
string-vectors, torn down in this order: the vector at +0x50
(begin +0x50, end +0x58, capacity end +0x60), then the vector
at +0x38 (begin +0x38, end +0x40, capacity end +0x48), then
the vector at +0x08 (begin +0x08, end +0x10, capacity end
+0x18). Each vector walk visits 0x20-byte elements in order.
Per element, the data pointer at +0x00 is compared against
the element's own +0x10 slot address: on equality the string
is in short form and nothing is freed; otherwise the sized
delete (PLT 0x63f0d80) frees capacity + 1 bytes, where
capacity is the element's +0x10 field. After a vector's
elements, the vector's own buffer is freed as one span
(capacity end minus begin) whenever the begin pointer is
non-null; a null begin frees nothing for that vector. The
third vector's span free is combined with the record advance:
when its begin is null the code jumps straight to the
advance, otherwise it frees the span and then advances.

Record fields outside the three vectors (+0x00..+0x08,
+0x20..+0x38, +0x68..+0x70) are never read by this routine,
so their roles are not claimed.

Exit. Once the record cursor reaches the end pointer, the
holder begin is reloaded: a null begin returns plainly with
nothing freed, otherwise the holder buffer span ([holder+0x10]
minus [holder+0x00]) is freed by a tail jump to the same
sized-delete PLT. The holder itself is never freed. Note the
exit span free runs even for an empty vector whose begin is
non-null.

Consumers (executable-LOAD-segment exhaustive E8/E9 scan with
objdump confirmation, reproduced by the packet's census.py and
re-run inside verify.py): exactly 1 direct call + 0 tail
jumps, at 0x5d7d72c in the caller FDE 0x5d7d5a8..0x5d7d740.
At the site rdi is loaded from rbx immediately before the
call. The caller frame is a cleanup fragment: its code calls
__cxa_begin_catch, __cxa_end_catch and __cxa_rethrow nearby,
and the fragment is entered by a tail jump from the
personality stub at 0x5d7dd4d (FDE 0x5d7d740..0x5d7dd9a).
The owning function behind that fragment is not pinned and
is recorded as an unknown; the register provenance of rbx
beyond the load is likewise not pinned. 0 stored qwords in
a full-file 8-byte scan, 0 RELATIVE relocations — reached
only by code, never by data.

Relation to neighbouring work: unlike the single-holder
teardowns #2728, #2733, #2740 and #2742, this packet pins a
vector-of-records destructor; unlike the record-vector
destructor #2737 (0x300-byte records, thirteen per-record
phases), this pins 0x70-byte records with exactly three
string-vector phases and a cleanup-fragment sole caller.
It is a complete behavior (outer loop, three per-record
phases, exit span free, and the sole consumer), not a
lone-window fragment.

## Evidence notes

The packet's JSON holds semantic records only. Detail at the
code level lives in the raw disassembly excerpt text files,
kept verbatim and whole-function: main.txt is the full
routine, and caller_sites.txt holds a verbatim 32-byte
window starting exactly at the call site. The excerpts were
produced with objdump, exactly as recorded in
export_excerpts.py, and verify.py regenerates them
byte-for-byte from fresh objdump runs on the real binary.
Mnemonics such as `endbr64` in those excerpts are genuine
instructions present in the target binary, not placeholders.

The objdump commands used are:

    objdump -d --start-address=0x5d5ae50 --stop-address=0x5d5afe8 work/hl-node-115.bin
    objdump -d --start-address=0x5d7d72c --stop-address=0x5d7d74c work/hl-node-115.bin

The readelf command used for frames.txt is:

    readelf --debug-dump=frames work/hl-node-115.bin
