# RE-001: map node #115 nested array teardown 0x5d58f10 with its per-element string dispose and ten callers

Bounded question: what does node #115 routine 0x5d58f10 (FDE
0x5d58f10..0x5d58fab, 155 bytes) do to the holder in rdi, end to end?

## Answer

It is a nested array teardown that frees its own inner holder, not
a plain list drain: it walks an array of pointers, disposes a
string inside each pointed-to struct, frees each struct, frees
the array buffer, and finally frees the inner object itself. It
pushes r13/r12/rbp/rbx and reserves 8 bytes of stack, and it
performs no canary check.

Inner load. The holder in rdi points at an inner object:
inner = [holder]. A null inner returns plainly with nothing
freed — the outer holder itself is never freed in any path.

Array phase. The inner object holds a vector-like triple of
8-byte pointers: begin at +0x00, end at +0x08, capacity end at
+0x10. The loop walks [begin, end) in steps of 8. A null
element pointer is skipped. Otherwise the element points at a
0x20-byte struct whose first field is a string: the string
pointer at element+0x00 is compared against element+0x10, and
when they differ the string is freed with a sized delete of
(capacity + 1), capacity read from element+0x10, through the
_ZdlPvm PLT at 0x63f0d80. The element struct itself is then
freed with a sized delete of exactly 0x20 through the same PLT.
The qword at element+0x08 is never read; its role is not
claimed.

Buffer phase. Begin is reloaded from inner+0x00 and capacity
end from inner+0x10. When begin is non-null the array buffer
is freed with a sized delete of (capacity end - begin) bytes.
A null begin skips this free, and the inner free below still
runs. Note the buffer free uses the capacity end, not the loop
end, so the freed span covers the whole allocation.

Exit. The routine tail-jumps to the sized-delete PLT freeing
the inner object itself at exactly 0x18. The outer holder in
rdi is never freed.

Consumers (executable-LOAD-segment exhaustive E8/E9 scan with objdump
confirmation, reproduced by the packet's census.py and re-run inside
verify.py): exactly 10 direct calls + 0 tail jumps across 9 caller
FDEs (see callers.tsv for the site list and the rdi source at each
site: frame-relative holders such as lea -0x248(%rbp) and
lea -0x328(%rbp), and rbx-relative holders such as lea 0x8(%rbx),
lea 0x260(%rbx) and lea 0xb0(%rbx)); 0 stored qwords in a
full-file 8-byte scan, 0 RELATIVE relocations — reached only by
code, never by data. What any caller does with the holder before
or after the call is not claimed here.

Relation to neighbouring work: distinct from the list teardown
0x5d59780 (#2725: a linked chain of 0x38-byte nodes, holder
never freed) and from the plain list free 0x5d596f0 (#2728:
0x18-byte nodes, no per-node disposal, holder never freed).
This routine walks a pointer array rather than a chain, disposes
a string inside each element, and — unlike both of those — frees
the inner holder itself at the end. The sized-delete PLT and
the string guard idiom are shared vocabulary of the holder
layout, not a repeated claim: the pinned behavior here is the
array walk plus the inner self-free.

## Evidence notes

The raw excerpts in this packet are verbatim objdump output, kept
whole-function; the objdump command that produced each file is
recorded in export_excerpts.py. Instruction text such as `endbr64`
at the routine entry is a genuine instruction present in the target
binary, not a placeholder. The packet JSON holds semantic records
only, not a per-instruction list.

## Unknowns (not claimed)

- What role the qword at element+0x08 plays; it is never read
  by this routine.
- What source-level type the inner object or the element structs
  have; only the observed pointer arithmetic is pinned.
- What any caller function does with the holder before or after
  this call; only the call sites, their FDEs and the rdi source
  at each site are recorded.
- Behaviour on a corrupt array range, a capacity end before
  begin, or an element pointer that is not a 0x20-byte struct;
  the model requires a well-formed range.

## Verification

Run from the repository root:

    python3 research/work-items/RE-001-nested-array-teardown-58f10-115/verify.py
    python3 research/work-items/RE-001-nested-array-teardown-58f10-115/census.py

The checker binds the binary SHA-256 to provenance/artifacts.json,
regenerates every excerpt byte-for-byte from fresh objdump runs,
checks every main.txt line against the raw binary, re-runs the
caller census, and invokes the model tests in
tests/test_nested_array_teardown_58f10_115.py.
