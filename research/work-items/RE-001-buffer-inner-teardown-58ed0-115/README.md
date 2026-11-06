# RE-001: map node #115 buffer-inner teardown 0x5d58ed0 with its buffer free, fixed 0x18 inner free and three callers

Bounded question: what does node #115 routine 0x5d58ed0 (FDE
0x5d58ed0..0x5d58f02, 50 bytes) do to the holder in rdi, end to end?

## Answer

It is a buffer-inner teardown: it frees a heap object (the inner
object) together with the buffer that object owns, and nothing else.
It pushes rbx only, reserves no stack, and performs no canary check.

Inner gate. The holder in rdi points at an inner object:
inner = [holder+0x00]. A null inner returns plainly with nothing
freed — neither the buffer phase nor the inner free runs. The outer
holder itself is never freed in any path.

Buffer phase. When the inner object is non-null, its buffer pointer
is buffer = [inner+0x00]. A null buffer skips the buffer free
outright. Otherwise the buffer is freed with a sized delete of
([inner+0x10] - buffer) bytes through the _ZdlPvm PLT at 0x63f0d80:
the size is the capacity-end qword at inner+0x10 minus the buffer
begin, i.e. the full allocation span, not a used-length span. The
qword at inner+0x08 is never read by this routine, so no claim is
made about its role.

Exit. The routine then tail-jumps to the same sized-delete PLT
freeing the inner object itself at a fixed size of 0x18 bytes. This
exit runs whenever the inner object is non-null, whether the buffer
was freed or skipped for being null, and there is no second null
test on the inner pointer here — it is already known non-null from
the entry gate.

Consumers (executable-LOAD-segment exhaustive E8/E9 scan with objdump
confirmation, reproduced by the packet's census.py and re-run inside
verify.py): exactly 3 direct calls + 0 tail jumps across 2 caller
FDEs (see callers.tsv for the site list and the rdi source at each
site: a stack holder from mov -0x2d8(%rbp) and the register holder
rbx in the 0x5d60df2..0x5d60f99 caller, and the register holder r15
in the 0x5d789ce..0x5d78b40 caller); 0 stored qwords in a full-file
8-byte scan, 0 RELATIVE relocations — reached only by code, never
by data. What any caller does with the holder before or after the
call is not claimed here. Note the pairing: both caller functions
also call the nested array teardown 0x5d58f10 (#2729) nearby — in
the 0x5d789ce caller the 0x5d58f10 call at 0x5d78a28 is immediately
followed by this routine's call at 0x5d78a30 with r15 — so this
routine is the companion teardown for a second owned member, not a
re-statement of the nested teardown: it frees no per-element
strings, walks no array, and sizes its inner free at a fixed 0x18.

Relation to neighbouring work: distinct from the nested array
teardown 0x5d58f10 (#2729: an inner vector of 8-byte pointers with a
per-element string dispose, a buffer free and an inner self-free at
a fixed 0x18 — the fixed inner size matches, but the buffer phase
here is a single owned buffer, not a vector walk) and from the
chunked array teardown 0x5d58fb0 (#2732: fixed 0x200-byte chunk
frees from slots on the holder itself, sized inner free by a holder
count). This routine's shape — one buffer, one fixed-size inner
free, null-tolerant at both levels — is its own.

## Evidence notes

The raw excerpts in this packet are verbatim objdump output, kept
whole-function; the objdump command that produced each file is
recorded in export_excerpts.py. Text such as `endbr64` at the
routine entry is a genuine instruction present in the target
binary, not a placeholder. The packet JSON holds semantic records
only, not a per-instruction list.

## Unknowns (not claimed)

- What source-level type the holder, the inner object or the buffer
  have; only the observed pointer arithmetic is pinned.
- What the qword at inner+0x08 holds; it is never read by this
  routine.
- Whether [inner+0x10] is a source-level capacity end or some
  other bound; only the observed subtraction ([inner+0x10] -
  buffer) is pinned.
- What any caller function does with the holder before or after
  this call; only the call sites, their FDEs and the rdi source
  at each site are recorded.
- Behaviour on a corrupt buffer range (capacity end below the
  buffer begin) or a buffer pointer that is not a heap block of
  the computed size; the model requires a well-formed range.

## Verification

Run from the repository root:

    python3 research/work-items/RE-001-buffer-inner-teardown-58ed0-115/verify.py

It checks the binary digest against provenance/artifacts.json, the
packet manifest, byte-for-byte regeneration of the excerpts, every
main.txt line against the raw binary, the caller census, the empty
relocation census, the semantic-only records, and the model tests.
