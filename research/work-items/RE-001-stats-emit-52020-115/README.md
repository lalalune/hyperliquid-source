# RE-001: node #115 statistics emit 0x5d52020

## Bounded question

What does routine `0x5d52020` (FDE `0x5d52020..0x5d520c1`,
161 bytes) do with the object field at `+0x548`, and what does
it emit when that field is present?

## Answer, pinned to the target

The routine takes one argument -- an object pointer in `rdi` --
and returns void. End to end, in order:

1. **Gate.** Read the pointer at object `+0x548`. When it is
   null the routine returns at once: no produce call, no emit
   call, no disposal, nothing else read.
2. **Produce.** When the `+0x548` pointer is non-null, call the
   virtual method at vtable slot `0xe8` (the 29th pointer) of
   that object, with the stack temp slot at `rsp` as the hidden
   string-result slot and the `+0x548` pointer itself as the
   object argument (the System V C++ by-value-return shape:
   result slot in `rdi`, object in `rsi`). The callee is opaque
   here; what is pinned is that it fills a 32-byte string-shaped
   temp at `rsp` (pointer at `+0x00`, capacity-or-inline-buffer
   at `+0x10`).
3. **Emit.** Call `0x5fcf060` with five arguments, in order:
   `1`, the object field at `+0x360` (by address, not by
   value), the format string `"[%s:774] STATISTICS:\n %s"` at
   `0x4350a5`, the file string `"db/db_impl/db_impl.cc"` at
   `0x4451b9`, and the temp string's pointer. The callee is
   opaque; only the argument list and order are pinned. The
   argument shape matches the emit call of the neighbouring
   record-reset routine (level, sink by address, format, file,
   value), with level `1` here instead of `2`.
4. **Temp disposal**, by the std::string SSO rule: if the temp
   pointer differs from the temp's own `+0x10` slot address
   (heap form), delete it with size capacity `+ 1`, capacity
   read from the `+0x10` slot; inline form frees nothing. The
   temp size field at `+0x08` is never read by this routine.

The routine's own control transfers are exactly three direct
calls (emit, operator delete for the temp, and the
stack-canary failure call), one direct tail jump out (to the
cleanup block), and one indirect call (the virtual produce
call); it has no indirect tail jump. Its landing-pad entry at
`0x5d520b5` lies inside the FDE range, saves the incoming
value in `rbx`, and jumps to the cleanup block at
`0x5d51fec..0x5d52011`, just before the routine (after `int3`
padding at `0x5d52011..0x5d52020`); that block disposes the
temp string and resumes unwinding. It is recorded, not
modelled as a normal return. Bytes after the FDE range
(`0x5d520c1..0x5d520d0`) are `int3` padding, not a
landing-pad block.

## Consumers (site-only)

The census finds exactly one direct call site, no tail jumps:

- `0x5d7e339`, inside caller `0x5d7dfc0..0x5d7e627`.

Only the site and FDE range are claimed; caller argument
setup is not pinned here.

## NOT claimed

What the virtual produce callee computes, what the `+0x548`
object or the `+0x360` sink denote, how the emit callee
combines its arguments internally, caller semantics beyond the
site and FDE range, or behaviour on dangling pointers or a
null object pointer (the routine reads `+0x548`
unconditionally, so the model raises on a null object, stated
openly). The neighbouring routines are not part of this claim.

## Evidence

- Artifact: `artifacts/node/115/hl-node`, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (provenance/artifacts.json), materialised locally as
  `work/hl-node-115.bin` with the same hash.
- `main.txt`: the whole routine, verbatim, produced by
  `objdump -d --start-address=0x5d52020 --stop-address=0x5d520c1 work/hl-node-115.bin`.
  Instruction-level detail lives only in this excerpt text, not
  in `records.json`, which carries semantic records only.
  Mnemonics in the excerpt (including `endbr64` at the routine
  entry and at the landing-pad entry) are genuine instructions
  present in the target binary, not placeholders; `verify.py`
  checks every excerpt instruction byte-for-byte against the
  raw binary and against a fresh objdump run.
- `frames.txt`: the routine FDE line, the cleanup-block FDE
  line, and the caller FDE line, from
  `readelf --debug-dump=frames`.
- `callers.tsv`: the one call site with its caller FDE range,
  reproduced by `census.py`.
- `relocations.txt`: empty -- no RELATIVE relocation mentions
  the routine address.
- `records.json`: semantic records only (gate, produce
  argument list, emit argument list, disposal rule, census
  counts).
- `verify.py`, `export_excerpts.py`, `census.py`: the packet's
  own runnable checkers, committed in the packet.

## Reproduce

From the repository root, with GNU objdump/readelf (Binutils
2.42) and Python 3.12.3:

- `python3 research/work-items/RE-001-stats-emit-52020-115/export_excerpts.py`
- `python3 research/work-items/RE-001-stats-emit-52020-115/census.py`
- `python3 research/work-items/RE-001-stats-emit-52020-115/verify.py`
- `python3 tests/test_stats_emit_52020_115.py`

Repository-wide gates (`make verify`, `make test`,
`make catalogue-check`) are not claimed here: the baseline on
this machine is affected by missing LFS material and by the
absence of cargo/rustc, and this packet changes no
repository-wide behaviour. Only this packet's checker and the
model tests are claimed.

## Next step

The single caller at `0x5d7e339` and the virtual produce
callee behind slot `0xe8` are the natural follow-ups: what
string the slot produces, and what the caller does around
this emit.
