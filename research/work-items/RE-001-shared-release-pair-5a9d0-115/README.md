# RE-001: map node #115 shared-release pair 0x5d5a9d0 with its counted array drain, vector release and sole caller

Bounded question: what does node #115 routine 0x5d5a9d0 (FDE
0x5d5a9d0..0x5d5ab57, 391 bytes) do to the holder in rdi, end to
end, and who calls it?

## Answer

It releases two shared-pointer collections held by one holder,
without freeing any buffer and without freeing the holder
itself. The routine pushes r15/r14/r13/r12/rbp/rbx, reserves 8
stack bytes, and performs no canary check.

Release shape (shared by both phases). Each element carries a
control pointer at element+0x08; a null control is skipped. For
a live control, the count at control+0x08 is decremented: the
flag byte at 0x64ed290 selects the form — nonzero takes the
plain decrement path, zero takes the atomic `lock xadd`
decrement. When the old count is 1, the destroy helper
0x5d35070 is called with the control in rdi. When the count is
the sentinel 0x100000001, the cold block zeroes control+0x08
and calls the virtual slots 0x10 then 0x18 on the control's
object, and the loop continues. Element+0x00 is never read in
either phase, so no role is claimed for it.

Counted-array phase (first). The count lives at holder+0x00
and the element base pointer at holder+0x88, with a 0x10 stride.
The loop decrements the count first, then releases the element
at index (new count) — so the array drains from the last
element down to the first — and repeats until the count reaches
0. A zero count at entry skips this phase outright. The count
field ends at 0; the base pointer at holder+0x88 is not
changed and the array buffer is not freed.

Vector phase (second). The vector is (begin at holder+0x90,
end at holder+0x98), again with a 0x10 stride and the control
at element+0x08. The loop walks forward from begin to end,
releasing each element's control (null controls skipped, cursor
still advanced), and after the loop stores begin into end, so
the vector is logically emptied while its buffer is left in
place. An empty vector (begin equal to end) skips the loop and
leaves end unchanged, which is already equal to begin.

Consumer (executable-LOAD-segment exhaustive E8/E9 scan with
objdump confirmation, reproduced by the packet's census.py and
re-run inside verify.py): exactly 1 direct call + 0 tail jumps,
at 0x5d6bdbd inside the small caller function
0x5d6bdb0..0x5d6bdec, passing rdi from lea 0x10(%rsp). That
caller sits between a call to 0x60d52f0 and a call to
0x5d654c0, so this routine is one member cleanup inside a
larger holder cleanup sequence, not a standalone fragment. 0
stored qwords in a full-file 8-byte scan, 0 RELATIVE
relocations — reached only by code, never by data.

Relation to neighbouring work: the release shape is the same
shared-pointer release already seen inside the record-vector
destructor 0x5d59e00 (#2737), but this packet pins a different
fact: a standalone routine whose whole job is the two-phase
release — a counted array drained to zero plus a vector
released and reset — with its own sole caller. No buffer free
appears here, unlike the teardown routines #2728–#2742.

## Evidence notes

The packet's JSON holds semantic records only. Instruction-level
detail lives in the raw disassembly excerpt text files, kept
verbatim and whole-function: main.txt is the full routine, and
caller_sites.txt holds a verbatim 32-byte window starting
exactly at the call site. The excerpts were produced with
objdump, exactly as recorded in export_excerpts.py, and
verify.py regenerates them byte-for-byte from fresh objdump
runs on the real binary. Mnemonics such as `endbr64` in those
excerpts are genuine instructions present in the target binary,
not placeholders.

The objdump commands used are:

    objdump -d --start-address=0x5d5a9d0 --stop-address=0x5d5ab57 work/hl-node-115.bin
    objdump -d --start-address=0x5d6bdbd --stop-address=0x5d6bddd work/hl-node-115.bin

and frames.txt holds the routine FDE plus the caller FDE from
`readelf --debug-dump=frames work/hl-node-115.bin`.

## Unknowns

- Source-level types of the holder and the two collections;
  only sizes, strides and offsets are pinned.
- The source meaning of the flag byte at 0x64ed290 beyond
  selecting the plain versus atomic decrement; only the
  selection is pinned.
- Element+0x00 in both collections is never read by this
  routine; its role is not claimed.
- What the caller function does before or after the call, and
  what the released objects represent; the neighbouring calls
  at 0x60d52f0 and 0x5d654c0 are not pinned here.
- The destroy helper 0x5d35070 beyond its call contract
  (called with the control in rdi when the old count is 1);
  its internals are not re-pinned here.
