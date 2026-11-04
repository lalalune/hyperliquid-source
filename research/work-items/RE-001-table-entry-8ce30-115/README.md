# RE-001: node #115 indexed table entry 0x5d8ce30

## Bounded question

What does routine `0x5d8ce30` (FDE `0x5d8ce30..0x5d8ce53`,
35 bytes) return for an owner object and an index, and how is
it consumed by its one caller, the fallback lookup at
`0x5d52b60`? This resolves the stage-1 callee that the
fallback-lookup packet left opaque.

## Answer, pinned to the target

The routine takes two arguments -- an owner object pointer in
`rdi` and an index in `rsi` -- and returns one qword:

1. **Table bounds.** Load the table base from owner `+0x988`
   and the table end from owner `+0x990`. If the two are
   equal, the table is empty: return null (`xor %eax,%eax`)
   at once, without reading any entry.
2. **Entry load.** Otherwise shift the index left by 4 (a
   16-byte entry stride) and return the qword at
   `base + index * 16` -- the first qword of the index-th
   16-byte entry. No other entry field is read.

The routine writes nothing, makes no call of any kind, and
has no landing-pad entry inside its FDE range and no
exception cleanup block. The `nopl` at `0x5d8ce4d` is
alignment padding between the entry-load return and the
null-return path, inside the routine. Bytes after the FDE
range (`0x5d8ce53..0x5d8ce60`) are int3 padding, not a
landing-pad block; the next routine starts at `0x5d8ce60`.

## Consumer (site + argument setup, pinned)

The census finds exactly one direct call site, no tail
jumps: `0x5d52b76`, inside the fallback lookup
(`0x5d52b60..0x5d52ba9`). The fallback's own excerpt pins
the argument setup: it moves its `rsi` into `rdi`
(`0x5d52b68`) and its `rdx` into `rsi` (`0x5d52b6b`)
before the call, so this routine receives the fallback's
second argument as its owner object and the fallback's
third argument as its index. The fallback returns a
non-null result from this routine at once, so this routine
is stage 1 of the fallback's three-stage resolution: a
table hit short-circuits the array and default stages.
Only the site, the caller FDE range, and this argument
setup are claimed for the caller; the callers' other
behaviour is not pinned here.

## NOT claimed

What the owner object, the table, or the returned entry
qword denote; what the 16-byte entries contain past their
first qword; caller semantics beyond the site, the caller
FDE range, and the argument setup above; or behaviour on
dangling pointers, a null owner (the routine reads
`+0x988`/`+0x990` unconditionally, so the model raises on
a null owner, stated openly), or an out-of-range or
negative index (the binary reads past the table unchecked;
the model raises instead, stated openly).

## Evidence

- Artifact: `artifacts/node/115/hl-node`, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (provenance/artifacts.json), materialised locally as
  `work/hl-node-115.bin` with the same hash.
- `main.txt`: the whole routine, verbatim, produced by
  `objdump -d --start-address=0x5d8ce30 --stop-address=0x5d8ce53 work/hl-node-115.bin`.
  Instruction-level detail lives only in this excerpt text, not
  in `records.json`, which carries semantic records only.
  Mnemonics in the excerpt (including `endbr64` at the routine
  entry) are genuine instructions present in the target binary,
  not placeholders; `verify.py` checks every excerpt
  instruction byte-for-byte against the raw binary and against
  a fresh objdump run.
- `frames.txt`: the routine FDE line and the caller FDE line,
  from `readelf --debug-dump=frames`.
- `callers.tsv`: the one call site with its caller FDE range,
  reproduced by `census.py`.
- `relocations.txt`: empty -- no RELATIVE relocation mentions
  the routine address.
- `records.json`: semantic records only (table offsets and
  stride, empty-table rule, consumer site and argument setup,
  census counts).
- `verify.py`, `export_excerpts.py`, `census.py`: the packet's
  own runnable checkers, committed in the packet.

## Reproduce

From the repository root, with GNU objdump/readelf (Binutils
2.42) and Python 3.12.3:

- `python3 research/work-items/RE-001-table-entry-8ce30-115/export_excerpts.py`
- `python3 research/work-items/RE-001-table-entry-8ce30-115/census.py`
- `python3 research/work-items/RE-001-table-entry-8ce30-115/verify.py`
- `python3 tests/test_table_entry_8ce30_115.py`

Repository-wide gates (`make verify`, `make test`,
`make catalogue-check`) are not claimed here: the baseline on
this machine is affected by missing LFS material and by the
absence of cargo/rustc, and this packet changes no
repository-wide behaviour. Only this packet's checker and the
model tests are claimed.

## Next step

The neighbouring `0x5d52c80` lock-and-pop routine
(FDE `0x5d52c80..0x5d52ce8`) is a separate candidate, not
part of this claim; so is the `0x5d51ea0` virtual-dispatch
chain walk (FDE `0x5d51ea0..0x5d51feb`).
