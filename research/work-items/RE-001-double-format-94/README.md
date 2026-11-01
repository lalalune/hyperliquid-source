# RE-001: node #94 double formatter 0x514c050

## Bounded question

What does the 357-byte function at 0x514c050 in node #94 do with its
input, and how is the result stored in the output string object?

## Answer

It formats one double with the format string `%f` (bytes at 0x1df3ed)
into the output string object at `rdi`, using a 0x148-byte stack buffer
and `__vsnprintf_chk`. The formatted value is the first floating-point
vararg, carried in `xmm0`: every sampled caller sets `al = 1` and
computes a double into `xmm0` immediately before the call (integer
conversion, division and multiplication are all observed among the
callers). The named general-purpose arguments observed at all five call
sites are `rsi = [GOT 0x5778378]`, `rdx = 0x148`, `rcx = format 0x1df3ed`.

String object layout (observed): pointer at +0x0, length at +0x8,
union at +0x10 (heap capacity, or the 16-byte SSO buffer itself).

- SSO arm, `vsnprintf` return <= 15 (signed): pointer = own +0x10,
  length = return, bytes copied from the stack buffer, NUL at
  buffer + length.
- Heap arm, return > 15: `_M_create` is called with the length slot and
  old capacity 0; pointer = returned block, and both the union slot and
  the length slot receive the return value (exact fit: the capacity
  recorded equals the length, because no doubling adjustment applies
  with old capacity 0). Bytes are copied, NUL at pointer + length.

Supporting machinery, all observed in the bytes: a 0x1000-byte page
stack probe loop followed by a 0x150 probe before the buffer is used;
a `va_list` frame built on the stack (gp_offset 0x20, fp_offset 0x30,
overflow area `rbp+0x10`, register save area `rbp-0xd0`; the r8/r9 and
xmm0-xmm7 saves are skipped when `al == 0`); a stack canary from
`fs:0x28` stored at `rbp-0xd8` and checked on exit, with
`__stack_chk_fail` on mismatch and no return on that path. The function
returns the output string pointer in `rax`.

This function has no `endbr64` (it opens with `push %rbp`); the `int3`
bytes after the canary-fail call are padding to the next FDE at
0x514c050 + 0x170 = 0x514c1c0, not instructions.

## Callers (complete census, full .text direct-call byte scan)

| site | setup observed |
| --- | --- |
| 0x514cc9f | eax=1, xmm0 from a prior computation, rsi=[GOT], rdx=0x148, rcx=format |
| 0x5157e2e | eax=1, xmm0 = int-to-double then division |
| 0x51586d1 | eax=1, xmm0 = int-to-double, multiplication, division |
| 0x515956c | eax=1, xmm0 = int-to-double then division |
| 0x515a035 | eax=1, xmm0 loaded from the caller's frame (`movsd 0x28(%rbp)`) |

No tail jumps to this function were found. Caller excerpts in
`callers.objdump.txt` show 0x40 bytes before each site; the enclosing
FDE range per site is recorded in `records.json`.

## Observations, inferences, unknowns

Observations are the records in `records.json` and the verbatim excerpts.
Inferences: the formatted value is the first floating-point vararg;
heap-arm capacity equals the formatted length (see above). Unknowns:
the purpose of the incoming `rsi` value — the GOT slot at 0x5778378
carries a `R_X86_64_GLOB_DAT` relocation for `vsnprintf`, but the body
never reads `rsi`, so no role is claimed for it; behaviour for a
negative `vsnprintf` return (the signed compare would take the SSO
path) is not modelled, since `%f` formatting of a finite double does
not produce it; no source-level function or type name is claimed, and
objdump's nearest-symbol annotations are not symbol names.

## Neighbours

The preceding FDE at 0x514bfe0 is the object teardown bound in the
previous item of this series (two string disposals plus a sized
self-delete — a different protocol). The following FDE at 0x514c1c0 is
unexamined and is not claimed here.

## Verification

`python3 verify.py` — ALL CHECKS PASSED (target digest, function carve
SHA, padding, format bytes, call targets re-derived from raw rel32
encodings, FDE, GOT relocation, caller census, excerpt lines vs fresh
objdump, manifest hashes). `python3 export_excerpts.py` regenerates the
excerpt files. Bound to node #94, SHA-256
3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f
(provenance/artifacts.json).
