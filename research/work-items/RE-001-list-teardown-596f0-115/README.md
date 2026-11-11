# RE-001: map node #115 list teardown 0x5d596f0 with its plain node free and three callers

Bounded question: what does node #115 routine 0x5d596f0 (FDE
0x5d596f0..0x5d59777, 135 bytes) do to the holder in rdi, end to end?

## Answer

It is a list teardown followed by a buffer clear, not a
destructor: it drains a linked list, zeroes the list slots, clears
a counted buffer with memset, and conditionally frees that buffer
— but it never frees the holder itself, never clears the buffer
begin or count slots, and performs no canary check. It pushes
rbp/rbx and reserves 8 bytes of stack.

List phase. The list head lives at holder+0x10. A null head
skips the loop entirely. Otherwise the loop walks the chain
head to tail: the next pointer at node+0x00 is loaded before
each free, then the node is freed with a sized delete of exactly
0x18 through the _ZdlPvm PLT at 0x63f0d80. No per-node payload
is disposed — the node free is the whole per-node step, which is
what distinguishes this routine from the adjacent list teardown
0x5d59780 (covered by #2725), whose 0x38-byte nodes each carry a
string disposed before the node free.

Buffer phase. The count is loaded from holder+0x08 and the
begin from holder+0x00, and the buffer is cleared with
memset(begin, 0, count * 8) through the memset PLT at 0x63f0a90.
The begin and count are then reloaded, and the qwords at
holder+0x10 (the list head) and holder+0x18 are zeroed. The
exit compares the reloaded begin against holder+0x30: when
they are equal the routine returns plainly; otherwise it
tail-jumps to the sized-delete PLT freeing (begin, count * 8).
The begin slot (+0x00) and the count slot (+0x08) are not
cleared in either exit path. The holder+0x30 comparison is
recorded as an observed branch condition; reading that address
as inline storage is an inference, and the pinned facts are the
comparison itself and the exact free size.

Consumers (executable-LOAD-segment exhaustive E8/E9 scan with objdump
confirmation, reproduced by the packet's census.py and re-run inside
verify.py): exactly 3 direct calls + 0 tail jumps across 2 caller
FDEs (see callers.tsv); 0 stored qwords in a full-file 8-byte scan,
0 RELATIVE relocations — reached only by code, never by data. Two
of the calls sit in caller FDE 0x5d8479c..0x5d85475 (sites
0x5d84879 and 0x5d8496c, passing rdi from lea 0x16d8(%rbx) and
lea 0x15f0(%rbx) respectively); the third sits in caller FDE
0x5d878f0..0x5d887b0 (site 0x5d88258, passing rdi from
lea 0x16d8(%rbx)). What either caller does with the holder before
or after the call is not claimed here.

Relation to neighbouring work: distinct from the list teardown
0x5d59780 (#2725: 0x38-byte nodes with a per-node string
dispose) and from the record teardowns 0x5d593f0 (#2724) and
0x5d59510 (#2727), which walk fixed-stride arrays rather than a
pointer chain. The buffer tail (memset + slot zeroing + the
holder+0x30 exit test) is shared with #2725, which is a property
of the holder layout, not a repeated claim: the list phase pinned
here is different in node size and in the absence of any per-node
disposal.

## Evidence notes

The raw excerpts in this packet are verbatim objdump output, kept
whole-function; the objdump command that produced each file is
recorded in export_excerpts.py. Instruction text such as `endbr64`
at the routine entry is a genuine instruction present in the target
binary, not a placeholder. The packet JSON holds semantic records
only, not a per-instruction list.

## Unknowns (not claimed)

- What role the qword at holder+0x18 plays beyond being zeroed
  in the buffer phase; it is recorded as a zeroed slot only.
- Whether holder+0x30 is inline storage for the buffer; only the
  comparison and the free size are pinned.
- What either caller function does with the holder before or after
  this call; only the call sites and their FDEs are recorded.
- Behaviour on a cyclic or corrupt list, or on a count that does
  not match the buffer; the model requires a well-formed chain
  and a matching count.

## Verification

Run from the repository root:

    python3 research/work-items/RE-001-list-teardown-596f0-115/verify.py
    python3 research/work-items/RE-001-list-teardown-596f0-115/census.py

The checker binds the binary SHA-256 to provenance/artifacts.json,
regenerates every excerpt byte-for-byte from fresh objdump runs,
checks every main.txt line against the raw binary, re-runs the
caller census, and invokes the model tests in
tests/test_list_teardown_596f0_115.py.
