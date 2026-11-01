# RE-001: node #94 level-stats report builder (0x514c580)

Task ID: RE-001. Bounded question: what does the 462-byte function at
0x514c580 in node #94 compute, and how do its per-level lines get their
two columns? Answer: it appends a "Level Files Size(MB)" header and one
formatted line per level to an output string, where each level's file
count comes from a pointer span in the function itself and its size in
MiB comes from a small trampoline plus a sum function over the same span.

## Target binding

- Binary: node #94, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
  (provenance/artifacts.json), 91,774,280 bytes.
- Function: 0x514c580..0x514c74e, 462 bytes, FDE at .eh_frame+0x0029a8bc
  (length 0x5c, CIE 0x00000000), no int3 padding: the next FDE starts
  immediately at 0x514c74e.
- Stack frame: six callee-saved registers pushed (r15, r14, r13, r12,
  rbp, rbx), `sub $0x408, %rsp`; the stack canary sits at rsp+0x3f8
  and is checked on every exit path; the per-level line buffer is at
  rsp+0x10 and is exactly 1000 bytes (0x3e8), matching the snprintf
  limit. The function returns 1 on success.

## Observations (read from the bytes)

- Arguments: rdi = an outer object (kept in r14), rsi = the output
  string object (kept in r13, layout pointer +0x0, length +0x8,
  union +0x10, as in the neighbouring string work).
- Level count: the signed int32 at [outer+0x778]. If it is <= 0 the
  function returns 1 after the header; otherwise it loops with index
  ebx from 0 and a byte offset r12 from 0, stepping r12 by 0x18 per
  level, and stops when the count is <= the incremented index.
- Container chain: rax = [outer+0x788]; container = [rax+0x30]. Two
  stack slots are built from it: (rsp) = container+0x40 (the
  sub-object handed to the trampoline) and (rsp+0x8) = container.
  The level array pointer lives at [container+0xad8], which is the
  same field the trampoline reads as [sub-object+0xa98], since
  0x40 + 0xa98 = 0xad8. Level elements are 0x18 bytes: +0x0 begin
  pointer, +0x8 end pointer, +0x10 a third field read only by the
  sum function (its owning record type is not claimed here).
- Header: the line buffer is filled by three vector stores from
  .rodata (0x2091e0 at buffer+0, 0x207f80 at buffer+16, 0x209580 at
  buffer+27, overlapping as the compiler emitted them), giving the
  42-byte literal `Level Files Size(MB)\n--------------------\n`,
  measured with strlen and appended to the output string.
- Per-level line: the trampoline at 0x51cbcd0 is called with
  rdi = the sub-object and esi = the level index; it loads the array
  pointer from [rdi+0xa98], adds index*24, and tail-jumps to the sum
  function at 0x50047b0 with the element address in rdi. The sum
  function reads the element's (begin, end) pointer pair, counts
  (end-begin)/8 eight-byte pointers, and adds the +0x10 field of
  each pointer in the leading run of non-null pointers, stopping at
  the first null pointer; an empty span (begin == end) returns 0.
  Back in the main function, that int64 result is converted to a
  double as an *unsigned* value (the negative arm uses the
  shift/or/doubling sequence) and multiplied by the .rodata double
  at 0x20ab08, which is exactly 2^-20, so the size column is MiB.
  The file count for the same element is computed directly in the
  main function as (end-begin) arithmetic-shifted right by 3, where
  (begin, end) are read from the array element at
  [container+0xad8] + index*0x18.
- Line format: the .rodata format at 0x1e4801 is
  `%3d %8d %8.0f\n`, called through __snprintf_chk into the
  1000-byte line buffer with arguments (index, file count, MiB
  double), then appended to the output string with strlen.
- Append guard: before each append, remaining =
  0x3fffffffffffffff - current output length; if the new text is
  longer than remaining, the function throws length_error with the
  message `basic_string::append` (.rodata 0x1f822d, PLT 0x56604a0)
  instead of appending. Both the header append and every line
  append carry this guard.
- Exception cleanup: the landing-pad stub at 0x514c74e (own FDE at
  .eh_frame+0x00633dd8, length 0x1c, CIE 0x006205d0, 38 bytes, 12
  int3 padding to the next FDE at 0x514c780) moves the stack slot
  at (%rsp) to rdi, calls the destructor at 0x514b690, then
  _Unwind_Resume after the canary check. The following function
  0x514c780 has its own landing-pad stub at 0x514c8da that jumps
  to this same stub, so the cleanup is shared, not exclusive to
  this function; this packet does not claim which object (%rsp)
  denotes at pad entry beyond the slot the stub reads.
- Canary failure on any path calls __stack_chk_fail (PLT 0x5660430).

## Inferred rule (separated from observations above)

`build_report(count, spans)` returns 1 (the function returns 1; the
observable output is the appended text). It first appends the header
literal, then for each index i in 0..count-1 appends
`"%3d %8d %8.0f\n" % (i, files_i, mib_i)` where files_i is the
span's pointer count and mib_i is the span's summed +0x10 fields
converted to MiB. Every append is guarded by the length-error rule
above. The model in tools/foundation_level_report.py implements
exactly this rule; the sum function's early stop at the first null
pointer and its empty-span zero are part of the rule, not
approximations.

## Unknowns (explicit)

- The outer object, the container at [outer+0x788]+0x30, and the
  record type behind the level elements are not identified; only
  the field offsets the bytes actually use are claimed.
- The function has no direct e8 callers in a full objdump scan, so
  the path that reaches it (function pointer, virtual dispatch, or
  another mechanism) is not claimed.
- The trampoline's other three direct callers (0x4fb25e5,
  0x5151c72, 0x5151d44) are census evidence only; their arguments
  and purposes are not modelled.
- The element's +0x10 field is a byte count only by its use: the
  sum is scaled by 2^-20 and printed under a "Size(MB)" header.
  Its source-level name is not claimed.

## Neighbours

| FDE start | Size | Relation |
| --- | --- | --- |
| 0x514c520 | 96 bytes | Preceding FDE; the wrapper consumer of the 0x514c1c0 teardown, claimed by the previous work item, not re-claimed here |
| 0x514c780 | 358 bytes | Following FDE; the container-copy function whose landing-pad stub jumps to this item's cleanup; its own body is not claimed here |
| 0x51cbcd0 | 27 bytes | Size trampoline called once per level from this function |
| 0x50047b0 | 62 bytes | Sum function reached only through the trampoline's tail jump |

Instruction-level detail lives only in the raw objdump excerpts
(window.objdump.txt, cleanup.objdump.txt, trampoline.objdump.txt,
sum.objdump.txt, plt.objdump.txt), kept verbatim and whole-function.
The mnemonics in those excerpts (including endbr64) are the genuine
instructions emitted by objdump for this binary, not placeholders.
records.json carries semantic records only, never a per-instruction
mnemonic list.
