# RE-001: map node #115 chunked array teardown 0x5d58fb0 with its 0x200-byte chunk frees and seven callers

Bounded question: what does node #115 routine 0x5d58fb0 (FDE
0x5d58fb0..0x5d59015, 101 bytes) do to the holder in rdi, end to end?

## Answer

It is a chunked array teardown: it frees a run of fixed-size 0x200-byte
chunks pointed to by slots on the holder itself, then frees the inner
object the holder points at, sized by a qword count on the holder. It
pushes r12/rbp/rbx, reserves no stack, and performs no canary check.

Inner gate. The holder in rdi points at an inner object:
inner = [holder+0x00]. A null inner returns plainly with nothing
freed — neither the chunk phase nor the inner free runs, even though
the chunk slots live on the holder, not on the inner object. The outer
holder itself is never freed in any path.

Chunk phase. The holder carries a chunk-pointer slot range: the cursor
starts at [holder+0x28] and the bound base is [holder+0x48]. The loop
runs while the cursor is below [holder+0x48] + 8 (unsigned comparison),
stepping 8, so the slot at [holder+0x48] itself is included. Per slot
the pointer is freed with a sized delete of exactly 0x200 through the
_ZdlPvm PLT at 0x63f0d80. There is no null test on slot pointers: every
slot's pointer is passed to the sized delete unconditionally, and the
cursor is advanced before the call, so the frees follow slot order.
When the cursor is already at or past the bound at entry, the loop is
skipped outright and control reaches the exit with rdi still holding
the inner pointer (the reload at 0x5d58ff6 exists only for the
loop-taken path).

Exit. The routine tail-jumps to the sized-delete PLT freeing the inner
object at ([holder+0x00], [holder+0x08] * 8): the count qword at
holder+0x08 is shifted left by 3 to form the byte size. This exit runs
whenever the inner object is non-null, whether the loop ran or was
skipped, and there is no null test on the inner pointer at this point
either — it is already known non-null from the entry gate.

Consumers (executable-LOAD-segment exhaustive E8/E9 scan with objdump
confirmation, reproduced by the packet's census.py and re-run inside
verify.py): exactly 7 direct calls + 0 tail jumps across 6 caller
FDEs (see callers.tsv for the site list and the rdi source at each
site: rbx-relative holders such as lea 0x18d8(%rbx), stack holders
such as mov 0x38(%rsp), mov 0x18(%rsp) and mov 0x88(%rsp), and
lea 0x60(%rsp)); 0 stored qwords in a full-file 8-byte scan,
0 RELATIVE relocations — reached only by code, never by data. What
any caller does with the holder before or after the call is not
claimed here.

Relation to neighbouring work: distinct from the nested array teardown
0x5d58f10 (#2729: an inner vector of 8-byte pointers with a
per-element string dispose, a buffer free and an inner self-free at a
fixed 0x18) and from the list teardowns 0x5d596f0 (#2728) and
0x5d59780 (#2725: linked chains, holder never freed). This routine
frees fixed 0x200-byte chunks from slots on the holder itself, gates
everything on the inner pointer, and sizes the inner free by a holder
count — a different shape from all three.

## Evidence notes

The raw excerpts in this packet are verbatim objdump output, kept
whole-function; the objdump command that produced each file is
recorded in export_excerpts.py. Instruction text such as `endbr64`
at the routine entry is a genuine instruction present in the target
binary, not a placeholder. The packet JSON holds semantic records
only, not a per-instruction list.

## Unknowns (not claimed)

- What source-level type the holder, the inner object or the chunks
  have; only the observed pointer arithmetic is pinned.
- What the holder fields between +0x28 and +0x48 (other than the two
  read as cursor base and bound base) hold; they are never read by
  this routine.
- Whether [holder+0x48] is a source-level end pointer with an
  off-by-one, or a last-slot pointer; only the observed
  cursor < bound + 8 comparison is pinned.
- What any caller function does with the holder before or after
  this call; only the call sites, their FDEs and the rdi source
  at each site are recorded.
- Behaviour on a corrupt slot range or a chunk pointer that is not
  a 0x200-byte block; the model requires a well-formed range.

## Verification

Run from the repository root:

    python3 research/work-items/RE-001-chunked-array-teardown-58fb0-115/verify.py

It checks the binary digest against provenance/artifacts.json, the
packet manifest, byte-for-byte regeneration of the excerpts, every
main.txt line against the raw binary, the caller census, the empty
relocation census, the semantic-only records, and the model tests.
