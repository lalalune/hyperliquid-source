# RE-001: node #115 three-stage fallback lookup 0x5d52b60

## Bounded question

What does routine `0x5d52b60` (FDE `0x5d52b60..0x5d52ba9`,
73 bytes) return for an object, a query value, and an index,
and in what order does it try its sources?

## Answer, pinned to the target

The routine takes three arguments -- an object pointer in
`rdi`, a query value in `rsi`, and an index in `rdx` -- and
returns one pointer, resolved in order:

1. **Callee.** Call `0x5d8ce30` (FDE `0x5d8ce30..0x5d8ce53`)
   with the original `rsi` as the first argument and the
   original `rdx` as the second. A non-null result is returned
   at once; nothing else is read. The callee is opaque here;
   only its argument list and order are pinned.
2. **Array.** Read the pointer array at object `+0xd10` and
   take entry `[index]` (8-byte stride, so the index counts
   pointers, not bytes). A non-null entry is returned. The
   index used here is the value saved in `rbx` before the
   callee call, so it is the same index the callee received,
   even though the callee may clobber `rdx`.
3. **Default.** Return the pointer at object `+0xd08`,
   whatever it is -- including null when the default slot
   itself is null.

The routine writes nothing and makes no other call. The
three returns share one epilogue (`0x5d52b80..0x5d52b86`):
the array-miss path jumps there after loading the default,
and the callee-hit and array-hit paths branch there directly.
The routine's one internal jump (`0x5d52ba7` to `0x5d52b80`)
lands inside the routine, so it is not a tail jump out.
There is no landing-pad entry inside the FDE range and no
exception cleanup block for this routine.

## Consumers (site-only)

The census finds exactly six direct call sites, no tail
jumps:

- `0x5de34a6`, inside caller `0x5de3340..0x5de404e`.
- `0x5de52e0`, inside caller `0x5de44c0..0x5de7ed0`.
- `0x5df2fc5` and `0x5df2fe8`, inside caller
  `0x5df2380..0x5df3659`.
- `0x5df4ca4` and `0x5df4cc3`, inside caller
  `0x5df3dd0..0x5df64b6`.

Only the sites and FDE ranges are claimed; caller argument
setup is not pinned here.

## NOT claimed

What the callee at `0x5d8ce30` computes from (query, index),
what the object, the `+0xd10` array, or the `+0xd08` default
slot denote, caller semantics beyond the site and FDE range,
or behaviour on dangling pointers, a null object pointer
(the routine reads `+0xd10`/`+0xd08` on the miss paths, so
the model raises on a null object, stated openly), or an
out-of-range index (the binary reads past the array
unchecked; the model raises instead, stated openly).

## Evidence

- Artifact: `artifacts/node/115/hl-node`, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (provenance/artifacts.json), materialised locally as
  `work/hl-node-115.bin` with the same hash.
- `main.txt`: the whole routine, verbatim, produced by
  `objdump -d --start-address=0x5d52b60 --stop-address=0x5d52ba9 work/hl-node-115.bin`.
  Instruction-level detail lives only in this excerpt text, not
  in `records.json`, which carries semantic records only.
  Mnemonics in the excerpt (including `endbr64` at the routine
  entry) are genuine instructions present in the target binary,
  not placeholders; `verify.py` checks every excerpt
  instruction byte-for-byte against the raw binary and against
  a fresh objdump run.
- `frames.txt`: the routine FDE line, the callee FDE line,
  and the caller FDE lines, from
  `readelf --debug-dump=frames`.
- `callers.tsv`: the six call sites with their caller FDE
  ranges, reproduced by `census.py`.
- `relocations.txt`: empty -- no RELATIVE relocation mentions
  the routine address.
- `records.json`: semantic records only (stages, callee
  argument list, field offsets, census counts).
- `verify.py`, `export_excerpts.py`, `census.py`: the packet's
  own runnable checkers, committed in the packet.

## Reproduce

From the repository root, with GNU objdump/readelf (Binutils
2.42) and Python 3.12.3:

- `python3 research/work-items/RE-001-fallback-lookup-52b60-115/export_excerpts.py`
- `python3 research/work-items/RE-001-fallback-lookup-52b60-115/census.py`
- `python3 research/work-items/RE-001-fallback-lookup-52b60-115/verify.py`
- `python3 tests/test_fallback_lookup_52b60_115.py`

Repository-wide gates (`make verify`, `make test`,
`make catalogue-check`) are not claimed here: the baseline on
this machine is affected by missing LFS material and by the
absence of cargo/rustc, and this packet changes no
repository-wide behaviour. Only this packet's checker and the
model tests are claimed.

## Next step

What the six callers pass as (query, index) and what the
callee at `0x5d8ce30` (35 bytes) computes from them; the
neighbouring `0x5d52c80` lock-and-pop routine is a separate
candidate, not part of this claim.
