# RE-001: map node #115 object destructor 0x5d5b3a0 with its sole caller

Bounded question: what does node #115 routine 0x5d5b3a0 (FDE
0x5d5b3a0..0x5d5b4b7, 279 bytes) tear down, in what order, and
who calls it?

## Answer

It is a whole-object destructor for a holder at rdi, and returns
nothing. The routine pushes rbp and rbx, reserves 8 bytes of
stack, and performs no canary check. The holder itself is never
freed. Its phases run in this fixed order:

1. Member at +0x160: if non-null, released via the shared-release
   helper 0x5d350c0 (whose contract is pinned in the #2737
   packet).
2. Member at +0x110: passed to callee 0x60d5170. That callee's
   body is not pinned here; only the call is recorded, plus the
   observation that the callee opens with a pthread_mutex_destroy
   PLT call, so whether the member is a mutex is an inference,
   not a pinned fact.
3. List at +0xe8: every 0x18-byte plain node is freed with a
   sized delete of exactly 0x18 via the _ZdlPvm PLT 0x63f0d80.
   The next pointer at node +0x00 is loaded before the free, so
   the walk survives the free. No node field other than +0x00
   is read.
4. Buffer at +0xd8 (always runs, even for a null begin with
   count 0): memset (begin, 0, count * 8) via the memset PLT
   0x63f0a90, where count is the qword at +0xe0; then +0xf0 and
   +0xe8 are zeroed; then, unless begin equals the holder's own
   inline storage at +0x108, the buffer is freed by a sized
   delete of (begin, count * 8).
5. Members at +0xd0, +0xc0 and +0xb0, in that order: each, if
   non-null, released via helper 0x5d350c0.
6. Sub-holder at +0x58: cleared by callee 0x5d5b300, which
   frees that sub-holder's list of 0x50-byte two-string nodes
   and zeroes its buffer but does not free its buffer.
7. Sub-holder buffer: begin at +0x58, count at +0x60. Unless
   begin equals the sub-holder's own inline storage at +0x88,
   the buffer is freed by a tail jump to the sized-delete PLT
   with size count * 8; for an inline begin the routine returns
   plainly. A null begin with count 0 still reaches the tail
   jump with size 0.

Holder fields outside the named members are never read here,
so their roles are not claimed.

Consumers (executable-LOAD-segment exhaustive E8/E9 scan with
objdump confirmation, reproduced by the packet's census.py and
re-run inside verify.py): exactly 1 direct call + 0 tail
jumps, at 0x5d8489f in caller FDE 0x5d8479c..0x5d85475,
with rdi = lea 0x1518(%rbx), a member of the owning object.
0 stored qwords in a full-file 8-byte scan, 0 RELATIVE
relocations — reached only by code, never by data. The same
caller FDE also calls the plain list teardown 0x5d596f0
pinned in #2728 just before this routine and routine
0x5d5a8d0 just after it; this packet pins a different
routine with its own phases, not a restatement of either.

Relation to neighbouring work: unlike the single-holder
teardowns #2728, #2740 and #2742, this pins a multi-phase
object destructor — four shared releases, a member call, a
list drain, a buffer clear-and-free, a sub-holder clear and
a tail buffer free — with its sole consumer. It is a complete
behavior (all seven phases plus the consumer), not a
lone-window fragment.

## Evidence notes

The packet's JSON holds semantic records only. Detail at the
code level lives in the raw disassembly excerpt text files,
kept verbatim and whole-function: main.txt is the full
routine, caller_sites.txt is a 32-byte window at the call
site, frames.txt holds the routine FDE plus the caller FDE.
The raw excerpts are exactly as objdump emitted them; tokens
such as `endbr64` are genuine code present in the target
binary, not placeholders. verify.py and census.py are committed
in the packet, and export_excerpts.py regenerates the excerpts
byte-for-byte from fresh objdump runs, so the checker behind
"ALL CHECKS PASSED" is visible in the diff instead of only
claimed here. The model in tools/object_destructor_5b3a0_115.py
and its tests in tests/test_object_destructor_5b3a0_115.py
exercise the behavior end to end: holder state in, ordered
observable-effect trace out, including the boundary cases
(null members, empty list, null begin with count 0, inline
buffers on both buffer phases).
