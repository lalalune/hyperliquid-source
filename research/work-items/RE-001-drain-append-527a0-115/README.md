# RE-001: map node #115 drain-and-append 0x5d527a0 with its deque growth and two callers

Bounded question: what does node #115 routine 0x5d527a0 (FDE
0x5d527a0..0x5d52b60, 960 bytes) move, where does it put it, and
who calls it?

## Answer

It drains a chunked source range into a deque-style destination
and then resets the source, returning nothing. The routine pushes
r15, r14, r13, r12, rbp and rbx, reserves 0x28 bytes of stack, and
performs no canary check.

The source (rsi) holds a base count at +0x148, an inline table of
eight qwords at +0x190, and a heap range at +0x198 (begin) and
+0x1a0 (end). The drain count is base + (heap end - heap begin)
// 8. Element i comes from the inline table for i < 8 and from
the heap array at heap begin + (i - 8) * 8 for i >= 8. When the
count is 0 the routine returns at once, after one guard call and
before any append or source reset.

Per element the routine calls the guard at 0x60d5390 with the
member at owner +0x700 — once at entry and once per element — and
then appends the element qword to the destination deque at owner
+0x1388. That callee is endbr64; ret only (pinned already in the
RE-001-chain-dispatch-52d70-115 packet), so it changes nothing
observable.

The destination is a deque: chunk-pointer map at +0x1388 with its
slot count at +0x1390, a start iterator (current +0x1398, first
+0x13a0, last +0x13a8, node +0x13b0) and a finish iterator
(current +0x13b8, first +0x13c0, last +0x13c8, node +0x13d0),
with 0x200-byte chunks holding 64 qwords. The fast path stores
the element at the finish cursor and advances it by one slot.
The growth path runs when the finish slot is 63, the last slot
of the finish chunk:

- Size check first: size = (finish node - start node - 1) * 64 +
  finish slot used + start chunk remaining; a size of exactly
  0xfffffffffffffff throws the length error (PLT 0x63f0de0).
- When the map has a free slot after the finish node (map size
  minus finish node index is 2 or more), one 0x200-byte chunk is
  allocated via operator new (PLT 0x63f0dd0) and stored at
  map[finish node + 1]; the element fills the last slot of the
  old finish chunk, and the finish iterator moves to the new
  chunk at slot 0.
- When one or fewer free slots remain, the map is reallocated:
  if 2 * (node span + 2) < map size, the node pointers move
  inside the same map to map + ((map size - span - 2) // 2) * 8
  with memmove; otherwise a new map of 2 * (map size + 1) slots
  is allocated (3 slots when the map is empty), the node pointers
  are centred at new map + ((new slots - span - 2) // 2) * 8,
  copied with memmove (a single qword copied directly when the
  byte count is exactly 8), and the old map is freed with a sized
  delete of old size * 8. A new slot count above
  0xfffffffffffffff throws bad-array-new-length when the count
  shifted right by 61 is nonzero, else bad-alloc. The chunk
  allocation then runs as above.

After the loop the source is reset: the base at +0x148 is zeroed
when nonzero, and the heap end at +0x1a0 is set to the heap begin
at +0x198 when they differ, draining the source range.

Inference, kept separate from the observations above: the
destination layout matches a std::deque, and the growth path is
its push-back auxiliary plus map reallocation. The value type's
name is not in the binary. The base-equals-8-when-heap-non-empty
invariant is an assumption: the routine reads inline slots 0..7
and heap slots from index 8 on without checking it.

Consumers (executable-LOAD-segment exhaustive E8/E9 scan with
objdump confirmation, reproduced by the packet's census.py and
re-run inside verify.py): exactly 2 direct calls + 0 tail
jumps, at 0x5d5ff37 in caller FDE 0x5d5fec0..0x5d6008a (guarded
by the byte at rbx +0x18 being nonzero; rdi = (%rbx), rsi =
rbp) and at 0x5edc0e7 in caller FDE 0x5edbac0..0x5edc3b3 (rdi =
rbp, rsi = 0x18(%rsp)). 0 stored qwords in a full-file 8-byte
scan, 0 RELATIVE relocations — reached only by code, never by
data.

Relation to neighbouring work: unlike the teardown routines
#2728–#2762 and #2971, this pins a construction — a drain into a
growing deque — with its chunk allocation, map reallocation and
length-error arms. Caller FDE 0x5d5fec0..0x5d6008a also hosts a
chain-dispatch call at 0x5d5ff71 pinned in the
RE-001-chain-dispatch-52d70-115 packet, and caller FDE
0x5edbac0..0x5edc3b3 also hosts one at 0x5edc11d in the same
packet; this packet pins a different routine in those functions.

## Evidence notes

The packet's JSON holds semantic records only. Detail at the
code level lives in the raw disassembly excerpt text files,
kept verbatim and whole-function: main.txt is the full
routine, site-5d5ff37.txt and site-5edc0e7.txt are the verbatim
call-site windows (argument setup plus the call itself plus the
immediate post-call step), guard.txt is the whole 5-byte guard
callee, frames.txt holds the routine FDE, the guard FDE and the
two caller FDEs. The raw excerpts are exactly as objdump emitted
them; tokens such as `endbr64` are genuine code present in the
target binary, not placeholders. verify.py and census.py are
committed in the packet, and export_excerpts.py regenerates the
excerpts byte-for-byte from fresh objdump runs, so the checker
behind "ALL CHECKS PASSED" is visible in the diff instead of
only claimed here. The model in tools/drain_append_527a0_115.py
and its tests in tests/test_drain_append_527a0_115.py exercise
the behavior end to end: drain counts and element order,
inline-then-heap fetch, fast-path and chunk-alloc growth, map
grow and recenter, the length-error boundary, the map-size
overflow arms, guard-call counts and the source reset.
