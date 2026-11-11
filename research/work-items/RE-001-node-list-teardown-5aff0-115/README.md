# RE-001: map node #115 node-list teardown 0x5d5aff0 with its two callers

Bounded question: what does node #115 routine 0x5d5aff0 (FDE
0x5d5aff0..0x5d5b077, 135 bytes) tear down, in what order, and
who calls it?

## Answer

It tears down a holder that owns a linked list of plain nodes
plus a qword buffer, and returns nothing. The routine pushes
rbp and rbx, reserves 8 bytes of stack, and performs no
canary check.

Holder. rdi is the holder pointer: buffer begin at +0x00,
qword slot count at +0x08, list head at +0x10.

List phase. The head at +0x10 is followed through each node's
+0x00 next pointer, and every node is freed with a sized
delete of exactly 0x10 bytes via the _ZdlPvm PLT 0x63f0d80.
The next pointer is loaded before the node is freed, so the
walk survives the free. A null head skips the phase. No node
field other than +0x00 is read, so node payload roles are not
claimed.

Buffer phase (always runs, even when the list phase skipped).
The buffer is zeroed with memset (begin, 0, count * 8) via
the memset PLT 0x63f0a90, with begin and count reloaded from
the holder. The fields at +0x10 and +0x18 are then zeroed.
Finally, unless the begin pointer equals the holder+0x30
address — the holder's own inline storage — the buffer is
freed by a tail jump to the same sized-delete PLT with size
count * 8. A null begin with count 0 still reaches that tail
jump with size 0. The holder itself is never freed.

Holder fields at +0x20..+0x30 are never read, and +0x18 is
only zeroed, so their roles are not claimed.

Consumers (executable-LOAD-segment exhaustive E8/E9 scan with
objdump confirmation, reproduced by the packet's census.py and
re-run inside verify.py): exactly 2 direct calls + 0 tail
jumps. At 0x5d821de, in caller FDE 0x5d8205c..0x5d82240, rdi
is loaded from the stack slot -0x878(%rbp) immediately before
the call. At 0x5d825c3, in caller FDE 0x5d82240..0x5d83d9a,
rdi is lea -0x7c0(%rbp), the same address stored to
-0x878(%rbp) immediately before the call. 0 stored qwords in
a full-file 8-byte scan, 0 RELATIVE relocations — reached
only by code, never by data.

Relation to neighbouring work: the same holder layout and
buffer tail appear in the plain list teardowns #2728
(0x18-byte nodes) and #2742 (0x38-byte nodes), but this packet
pins a different routine with 0x10-byte nodes and two
different callers; it is not a restatement of either. It is a
complete behavior (list phase, buffer phase, and both
consumers), not a lone-window fragment.

## Evidence notes

The packet's JSON holds semantic records only. Detail at the
code level lives in the raw disassembly excerpt text files,
kept verbatim and whole-function: main.txt is the full
routine, and caller_sites.txt holds verbatim 32-byte windows
starting exactly at each call site. The excerpts were
produced with objdump, exactly as recorded in
export_excerpts.py, and verify.py regenerates them
byte-for-byte from fresh objdump runs on the real binary.
Mnemonics such as `endbr64` in those excerpts are genuine
instructions present in the target binary, not placeholders.

The objdump commands used are:

    objdump -d --start-address=0x5d5aff0 --stop-address=0x5d5b077 work/hl-node-115.bin
    objdump -d --start-address=0x5d821de --stop-address=0x5d821fe work/hl-node-115.bin
    objdump -d --start-address=0x5d825c3 --stop-address=0x5d825e3 work/hl-node-115.bin

The readelf command used for frames.txt is:

    readelf --debug-dump=frames work/hl-node-115.bin
