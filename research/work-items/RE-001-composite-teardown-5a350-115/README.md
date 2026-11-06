# RE-001: map node #115 composite teardown 0x5d5a350 with its three callers

Bounded question: what does node #115 routine 0x5d5a350 (FDE
0x5d5a350..0x5d5a6aa, 858 bytes) tear down, in what order, and
who calls it?

## Answer

It is a whole-container teardown for a holder at rdi, and returns
nothing. The routine pushes r15, r14, r13, r12, rbp and rbx,
reserves 0x38 bytes of stack, and performs no canary check. The
holder itself is never freed. One 0x40-byte record is torn down
the same way wherever it appears: its 0x18-byte plain-node list
at +0x18 is drained first (the next pointer at node +0x00 is
loaded before each sized delete of exactly 0x18 via the
_ZdlPvm PLT 0x63f0d80); then its buffer at +0x08 is memset to
zero over count * 8 bytes (count at +0x10) via the memset PLT
0x63f0a90; then +0x20 and +0x18 are zeroed; then, unless the
buffer begin equals the record's own inline storage at record
+ 0x38, the buffer is freed by a sized delete of (begin,
count * 8). The buffer phase runs for every record, even for a
null begin with count 0. Record bytes at +0x00 are never read,
so no role is claimed for them.

Its phases run in this fixed order:

1. Middle chunks: for each chunk pointer in [holder+0x28 + 8,
   holder+0x48), each pointed-to 0x200-byte chunk holds eight
   0x40-byte records, torn down in order. This phase runs only
   when holder+0x28 + 8 < holder+0x48, so the first chunk's
   records are not torn down here.
2. First chunk's live records: records in [holder+0x10,
   holder+0x20), stepping 0x40. Runs only when the start and
   finish chunk pointers differ (holder+0x28 != holder+0x48).
3. Last chunk's live records: records in [holder+0x38,
   holder+0x30), stepping 0x40, when the start and finish chunk
   pointers differ. When they are the same chunk
   (holder+0x28 == holder+0x48), phases 1 and 2 are skipped and
   this phase instead walks records from holder+0x10 while not
   equal to holder+0x30, stepping 0x40.
4. Chunk blocks and pointer array: if holder+0x00 is null the
   routine returns plainly. Otherwise every 0x200-byte chunk
   pointed to by [holder+0x28, holder+0x48 + 8) is freed by a
   sized delete of exactly 0x200, and the routine tail-jumps to
   a sized delete of (holder+0x00, holder+0x08 * 8).

The end slot at holder +0x48 is read as the address of the last
chunk pointer: phase 1 stops before it, phase 4 includes it.

Inference, kept separate from the observations above: the holder
layout matches a std::deque — chunk-pointer map at +0x00 with
its slot count at +0x08, a start iterator (current +0x10,
first +0x18, last +0x20, chunk pointer +0x28) and a finish
iterator (current +0x30, first +0x38, last +0x40, chunk
pointer +0x48), with 0x200-byte buffers holding eight 0x40-byte
records. The value type's name is not in the binary. Holder
fields +0x18 and +0x40 are never read here, so their roles are
not claimed beyond that inference.

Consumers (executable-LOAD-segment exhaustive E8/E9 scan with
objdump confirmation, reproduced by the packet's census.py and
re-run inside verify.py): exactly 3 direct calls + 0 tail
jumps, at 0x5d84a13 in caller FDE 0x5d8479c..0x5d85475 and at
0x5d87d02 and 0x5d8844a in caller FDE 0x5d878f0..0x5d887b0,
all three passing rdi = lea 0x1278(%rbx), the same member of
the owning object. 0 stored qwords in a full-file 8-byte scan,
0 RELATIVE relocations — reached only by code, never by data.
At two of the three sites the routine is called just after the
string-list teardown 0x5d5a720 pinned in #2740 and the chunked
copy 0x5d5a6b0 (the #2735 triplet shape, not re-pinned here);
at the third site the chunked copy call precedes it.

Relation to neighbouring work: unlike the single-holder
teardowns #2728, #2740, #2742, #2756 and the object destructor
#2762, this pins a four-phase chunked-container teardown — the
middle-chunk loop, the first and last chunks' live ranges, the
single-chunk combined range, and the chunk-block plus map free
— with its three consumers. It is a complete behavior (all four
phases plus the consumers), not a lone-window fragment.

## Evidence notes

The packet's JSON holds semantic records only. Detail at the
code level lives in the raw disassembly excerpt text files,
kept verbatim and whole-function: main.txt is the full
routine, site-5d84a13.txt, site-5d87d02.txt and
site-5d8844a.txt are the verbatim call-site windows (argument
setup plus the call itself plus the immediate post-call step),
frames.txt holds the routine FDE plus the two caller FDEs.
The raw excerpts are exactly as objdump emitted them; tokens
such as `endbr64` are genuine code present in the target
binary, not placeholders. verify.py and census.py are committed
in the packet, and export_excerpts.py regenerates the excerpts
byte-for-byte from fresh objdump runs, so the checker behind
"ALL CHECKS PASSED" is visible in the diff instead of only
claimed here. The model in tools/composite_teardown_5a350_115.py
and its tests in tests/test_composite_teardown_5a350_115.py
exercise the behavior end to end: holder state in, ordered
observable-effect trace out, including the boundary cases
(single chunk with the combined range, empty container, null
map pointer with a plain return, inline record buffers, null
buffer begin with count 0, node order before the buffer free).
