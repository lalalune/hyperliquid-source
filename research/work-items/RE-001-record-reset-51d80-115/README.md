# RE-001: node #115 conditional record reset 0x5d51d80

## Bounded question

What does routine `0x5d51d80` (FDE `0x5d51d80..0x5d51e6e`,
238 bytes) do to a record, and under what conditions does it
act at all?

## Answer, pinned to the target

The routine takes two arguments -- an object pointer in `rdi`
and a record pointer in `rsi` -- and proceeds only when BOTH
gates pass:

1. The byte at record `+0x00` is non-zero. When it is zero the
   routine returns at once and the object flag is never read.
2. The byte at object `+0x333` is zero. When it is non-zero the
   routine returns at once, with no build, emit, disposal or
   reset.

On the proceed path, end to end, in order:

1. **Build.** Call `0x61cfed0` with the stack temp slot and the
   record. The callee is opaque here; what is pinned is that it
   fills a 32-byte string-shaped temp at `rsp` (pointer at
   `+0x00`, capacity-or-inline-buffer at `+0x10`).
2. **Emit.** Call `0x5fcf060` with five arguments, in order:
   `2`, the object field at `+0x360` (by address, not by
   value), the format string `"[%s:755] Ignoring error %s"` at
   `0x446402`, the file string `"db/db_impl/db_impl.cc"` at
   `0x4451b9`, and the temp string's pointer. The callee is
   opaque; only the argument list and order are pinned.
3. **Temp disposal**, by the std::string SSO rule: if the temp
   pointer differs from the temp's own `+0x10` slot address
   (heap form), delete it with size capacity `+ 1`, capacity
   read from the `+0x10` slot; inline form frees nothing. The
   temp size field at `+0x08` is never read by this routine.
4. **Record reset**: save the pointer at record `+0x08`, then
   write zero to record `+0x00` (4 bytes), `+0x04` (2 bytes)
   and `+0x08` (8 bytes).
5. **Conditional delete[]**: if the saved `+0x08` pointer was
   non-null, delete[] it -- the binary reaches delete[] through
   a tail jump to `0x63f0dc0`, identical in observable effect.
   A null saved pointer returns with no delete.

The routine's own control transfers are exactly four direct
calls (build, emit, operator delete for the temp, and the
stack-canary failure call), two direct tail jumps out (to
delete[] and to the cleanup block), and no indirect transfer
of any kind. Its landing-pad entry at `0x5d51e62` lies inside
the FDE range and jumps to the cleanup block at
`0x5d51d54..0x5d51d7f`, just before the routine (after one
`int3` byte at `0x5d51d53`); that block disposes the temp
string and resumes unwinding. It is recorded, not modelled as
a normal return.

## Consumers (site-only)

The census finds exactly four direct call sites, no tail
jumps:

- `0x5e626e4`, inside caller `0x5e62530..0x5e62954`.
- `0x5e628f0`, inside the same caller.
- `0x5e69a0b`, inside caller `0x5e68fd0..0x5e6b82a`.
- `0x5e6a932`, inside the same caller.

Only the sites and FDE ranges are claimed; caller argument
setup is not pinned here.

## NOT claimed

What the build or emit callees do with their arguments, what
the object or record denote, what the `+0x360` field denotes
beyond being passed by address, caller semantics beyond sites
and FDE ranges, or behaviour on dangling pointers or a null
object/record pointer (the routine reads record `+0x00`
unconditionally, so the model raises on a null pointer, stated
openly). The neighbouring routines are not part of this claim.

## Evidence

- Artifact: `artifacts/node/115/hl-node`, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (provenance/artifacts.json), materialised locally as
  `work/hl-node-115.bin` with the same hash.
- `main.txt`: the whole routine, verbatim, produced by
  `objdump -d --start-address=0x5d51d80 --stop-address=0x5d51e6e work/hl-node-115.bin`.
  Instruction-level detail lives only in this excerpt text, not
  in `records.json`, which carries semantic records only.
  Mnemonics in the excerpt (including `endbr64` at the routine
  entry and at the landing-pad entry) are genuine instructions
  present in the target binary, not placeholders; `verify.py`
  checks every excerpt instruction byte-for-byte against the
  raw binary and against a fresh objdump run.
- `frames.txt`: the routine FDE line and the two caller FDE
  lines, from `readelf --debug-dump=frames`.
- `callers.tsv`: all four call sites with their caller FDE
  ranges, reproduced by `census.py`.
- `relocations.txt`: empty -- no RELATIVE relocation mentions
  the routine address.
- `records.json`: semantic records only (gates, build/emit
  argument lists, disposal rule, reset order, census counts).
- `verify.py`, `export_excerpts.py`, `census.py`: the packet's
  own runnable checkers, committed in the packet.

## Reproduce

From the repository root, with GNU objdump/readelf (Binutils
2.42) and Python 3.12.3:

- `python3 research/work-items/RE-001-record-reset-51d80-115/export_excerpts.py`
- `python3 research/work-items/RE-001-record-reset-51d80-115/census.py`
- `python3 research/work-items/RE-001-record-reset-51d80-115/verify.py`
- `python3 tests/test_record_reset_51d80_115.py`

Repository-wide gates (`make verify`, `make test`,
`make catalogue-check`) are not claimed here: the baseline on
this machine is affected by missing LFS material and by the
absence of cargo/rustc, and this packet changes no
repository-wide behaviour. Only this packet's checker and the
new model tests are claimed green.

## Concrete next step

What the two callers do with the object before and after
calling this routine, and what the build callee at `0x61cfed0`
writes into the temp from the record, are the open follow-ups;
neither is claimed here.
